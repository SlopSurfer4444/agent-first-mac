/* Read-only public-libproc identity query. No argv, task port or process memory. */
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <mach/vm_prot.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_REGIONS 4096
#define MAX_ANCESTORS 16

static int unknown(const char *reason)
{
    printf("{\"state\":\"UNKNOWN\",\"reason\":\"%s\"}\n", reason);
    return 2;
}

static int info_for(pid_t pid, struct proc_bsdinfo *info)
{
    memset(info, 0, sizeof(*info));
    return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info, sizeof(*info)) == sizeof(*info)
        && info->pbi_pid == (uint32_t)pid && info->pbi_uid == getuid()
        && info->pbi_start_tvsec && info->pbi_start_tvusec < 1000000;
}

static int incarnation(pid_t pid, uint64_t seconds, uint64_t micros)
{
    struct proc_bsdinfo info;
    return info_for(pid, &info) && info.pbi_start_tvsec == seconds && info.pbi_start_tvusec == micros;
}

static int same_chain(const struct proc_bsdinfo *a, const struct proc_bsdinfo *b, int count)
{
    for (int i = 0; i < count; i++)
        if (a[i].pbi_pid != b[i].pbi_pid || a[i].pbi_ppid != b[i].pbi_ppid
            || a[i].pbi_pgid != b[i].pbi_pgid || a[i].pbi_start_tvsec != b[i].pbi_start_tvsec
            || a[i].pbi_start_tvusec != b[i].pbi_start_tvusec) return 0;
    return 1;
}

static int executable(pid_t pid, const char *expected)
{
    char path[PROC_PIDPATHINFO_MAXSIZE];
    memset(path, 0, sizeof(path));
    int count = proc_pidpath(pid, path, sizeof(path));
    return count > 0 && (size_t)count < sizeof(path) && memchr(path, 0, sizeof(path))
        && !strcmp(path, expected);
}

static int same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino
        && a->st_mode == b->st_mode && a->st_uid == b->st_uid
        && a->st_size == b->st_size
        && a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec
        && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec
        && a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec
        && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}

static int mapped_target(const struct proc_regionwithpathinfo *r,
                         const char *target, const struct stat *file)
{
    const struct vinfo_stat *s = &r->prp_vip.vip_vi.vi_stat;
    return (r->prp_prinfo.pri_protection & VM_PROT_EXECUTE)
        && memchr(r->prp_vip.vip_path, 0, sizeof(r->prp_vip.vip_path))
        && !strcmp(r->prp_vip.vip_path, target)
        && s->vst_dev == (uint32_t)file->st_dev && s->vst_ino == file->st_ino
        && s->vst_size == file->st_size && S_ISREG(s->vst_mode);
}

static int diagnostic_chain(pid_t pid, struct proc_bsdinfo *chain)
{
    int count=0;
    while (pid>1 && count<MAX_ANCESTORS)
    {
        if (!info_for(pid,&chain[count])) break;
        for (int j=0;j<count;j++) if (chain[j].pbi_pid==(uint32_t)pid) return count;
        pid=chain[count++].pbi_ppid;
    }
    return count;
}

static void json_string(const char *s)
{
    putchar('"');
    for (const unsigned char *p=(const unsigned char*)s;*p;p++)
    {
        if (*p=='"' || *p=='\\') { putchar('\\');putchar(*p); }
        else if (*p<32) printf("\\u%04x",*p);
        else putchar(*p);
    }
    putchar('"');
}

static int process_metadata(const char *pid_arg,const char *birth,const char *expected)
{
    char tail;int pid;uint64_t seconds,micros;
    if (sscanf(pid_arg,"%d%c",&pid,&tail)!=1 || pid<=1
        || sscanf(birth,"%" SCNu64 ":%" SCNu64 "%c",&seconds,&micros,&tail)!=2
        || !seconds || micros>=1000000) return unknown("invalid_arguments");
    alarm(1);
    struct proc_bsdinfo before,after;
    if (!info_for(pid,&before) || before.pbi_start_tvsec!=seconds || before.pbi_start_tvusec!=micros)
        return unknown("metadata_incarnation");
    char path[PROC_PIDPATHINFO_MAXSIZE],again[PROC_PIDPATHINFO_MAXSIZE];
    memset(path,0,sizeof(path));memset(again,0,sizeof(again));
    int count=proc_pidpath(pid,path,sizeof(path));
    if (count<=0 || (size_t)count>=sizeof(path) || !memchr(path,0,sizeof(path))) return unknown("metadata_executable");
    count=proc_pidpath(pid,again,sizeof(again));
    if (count<=0 || (size_t)count>=sizeof(again) || !info_for(pid,&after)
        || after.pbi_start_tvsec!=seconds || after.pbi_start_tvusec!=micros) return unknown("metadata_incarnation_after");
    int stable=same_chain(&before,&after,1) && !strcmp(path,again);
    printf("{\"state\":\"PROCESS_OBSERVED\",\"pid\":%d,\"birth\":\"%" PRIu64 ":%" PRIu64
           "\",\"ppid\":%u,\"group\":%u,\"snapshotStable\":%s,\"expectedExecutable\":%s,\"nativeExecutable\":",
           pid,seconds,micros,before.pbi_ppid,before.pbi_pgid,stable?"true":"false",!strcmp(path,expected)?"true":"false");
    json_string(path);printf("}\n");return 0;
}

int main(int argc, char **argv)
{
    if (argc==5 && !strcmp(argv[1],"--metadata")) return process_metadata(argv[2],argv[3],argv[4]);
    char tail;
    int parsed_pid = 0;
    uint64_t seconds = 0, micros = 0;
    if (argc != 5 || sscanf(argv[1], "%d%c", &parsed_pid, &tail) != 1
        || parsed_pid <= 1 || sscanf(argv[2], "%" SCNu64 ":%" SCNu64 "%c", &seconds, &micros, &tail) != 2
        || !seconds || micros >= 1000000 || argv[3][0] != '/' || argv[4][0] != '/')
        return unknown("invalid_arguments");

    /* Python caller adds a 2.5-second subprocess bound. No signal is sent to
     * the observed process; alarm applies only to this short-lived observer. */
    alarm(2);
    pid_t pid = parsed_pid;
    if (!incarnation(pid, seconds, micros)) return unknown("incarnation_before");
    if (!executable(pid, argv[3])) return unknown("executable_before");
    int fd = open(argv[4], O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return unknown("target_open");
    struct stat before, after, named;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_uid != getuid()
        || before.st_mode & 0022) { close(fd); return unknown("target_file"); }

    uint64_t address = 0;
    for (unsigned i = 0; i < MAX_REGIONS; i++)
    {
        struct proc_regionwithpathinfo r;
        memset(&r, 0, sizeof(r));
        int count = proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, address, &r, sizeof(r));
        if (count != sizeof(r)) { close(fd); return unknown("region_unavailable"); }
        uint64_t start = r.prp_prinfo.pri_address, size = r.prp_prinfo.pri_size;
        if (!size || start < address || start > UINT64_MAX - size || start + size <= address)
        { close(fd); return unknown("region_progress"); }
        if (mapped_target(&r, argv[4], &before))
        {
            int stable = !fstat(fd, &after) && !lstat(argv[4], &named)
                && same_file(&before, &after) && same_file(&before, &named)
                && executable(pid, argv[3]) && incarnation(pid, seconds, micros);
            if (!stable) { close(fd);return unknown("identity_changed"); }
            /* Unix ancestry is diagnostic: Wine double-forks normal PE children.
             * It is neither required nor accepted as a prefix ownership proof. */
            struct proc_bsdinfo chain[MAX_ANCESTORS], after_chain[MAX_ANCESTORS];
            int chain_count=diagnostic_chain(pid,chain);
            int after_count=diagnostic_chain(pid,after_chain);
            int ancestry_stable=chain_count>0 && chain_count==after_count && same_chain(chain,after_chain,chain_count);
            stable=incarnation(pid,seconds,micros) && executable(pid,argv[3])
                && !fstat(fd,&after) && !lstat(argv[4],&named)
                && same_file(&before,&after) && same_file(&before,&named);
            close(fd);
            if (!stable) return unknown("identity_changed_after_diagnostic");
            printf("{\"state\":\"MATCH_IMAGE\",\"pid\":%d,\"birth\":\"%" PRIu64 ":%" PRIu64
                   "\",\"mappedExecutable\":true,\"targetDev\":%" PRIu64 ",\"targetIno\":%" PRIu64
                   ",\"regionsExamined\":%u,\"ancestryStable\":%s,\"ancestry\":[", pid, seconds, micros,
                   (uint64_t)(uint32_t)before.st_dev, (uint64_t)before.st_ino, i + 1,ancestry_stable?"true":"false");
            for (int j = 0; j < chain_count; j++)
                printf("%s{\"pid\":%u,\"birth\":\"%" PRIu64 ":%" PRIu64 "\",\"ppid\":%u,\"group\":%u}",
                       j ? "," : "", chain[j].pbi_pid, chain[j].pbi_start_tvsec,
                       chain[j].pbi_start_tvusec, chain[j].pbi_ppid, chain[j].pbi_pgid);
            printf("]}\n");
            return 0;
        }
        address = start + size;
    }
    close(fd);
    return unknown("region_budget");
}
