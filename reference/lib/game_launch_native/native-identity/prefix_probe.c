/* Independent, read-only public FD graph observation. No argv/env/task port. */
#pragma push_macro("main")
#undef main
#define main image_probe_main
#include "probe.c"
#undef main
#pragma pop_macro("main")
#include <sys/socket.h>

#define MAX_FDS 8192
#define MAX_SOCKETS 1024
struct endpoint { int fd;uint64_t so,pcb,peer_so,peer_pcb; };
struct role_snapshot {
    struct proc_bsdinfo identity;
    char executable[PROC_PIDPATHINFO_MAXSIZE];
    struct endpoint endpoints[MAX_SOCKETS];
    unsigned count,zero_handles;
    int complete;
};

static int capture(pid_t pid,uint64_t seconds,uint64_t micros,struct role_snapshot *out)
{
    memset(out,0,sizeof(*out));
    if (!info_for(pid,&out->identity) || out->identity.pbi_start_tvsec!=seconds
        || out->identity.pbi_start_tvusec!=micros) return 0;
    int n=proc_pidpath(pid,out->executable,sizeof(out->executable));
    if (n<=0 || (size_t)n>=sizeof(out->executable)) return 0;
    struct proc_fdinfo fds[MAX_FDS];
    n=proc_pidinfo(pid,PROC_PIDLISTFDS,0,fds,sizeof(fds));
    if (n<=0 || n%(int)sizeof(fds[0]) || (size_t)n>=sizeof(fds)) return 0;
    out->complete=1;
    for (unsigned i=0;i<(unsigned)n/sizeof(fds[0]);i++)
    {
        if (fds[i].proc_fdtype!=PROX_FDTYPE_SOCKET) continue;
        struct socket_fdinfo socket;
        memset(&socket,0,sizeof(socket));
        if (proc_pidfdinfo(pid,fds[i].proc_fd,PROC_PIDFDSOCKETINFO,&socket,sizeof(socket))!=sizeof(socket))
        { out->complete=0;continue; }
        const struct socket_info *s=&socket.psi;
        if (s->soi_family!=AF_UNIX || s->soi_kind!=SOCKINFO_UN || s->soi_type!=SOCK_STREAM
            || !(s->soi_state&SOI_S_ISCONNECTED)) continue;
        struct endpoint e={fds[i].proc_fd,s->soi_so,s->soi_pcb,
            s->soi_proto.pri_un.unsi_conn_so,s->soi_proto.pri_un.unsi_conn_pcb};
        if (!e.so || !e.pcb || !e.peer_so || !e.peer_pcb) { out->zero_handles++;out->complete=0;continue; }
        int duplicate=0;
        for (unsigned j=0;j<out->count;j++) if (out->endpoints[j].so==e.so && out->endpoints[j].pcb==e.pcb) duplicate=1;
        if (duplicate) continue;
        if (out->count==MAX_SOCKETS) { out->complete=0;continue; }
        out->endpoints[out->count++]=e;
    }
    struct proc_bsdinfo after;
    return info_for(pid,&after) && same_chain(&out->identity,&after,1) && executable(pid,out->executable);
}

static int reciprocal(const struct endpoint *a,const struct endpoint *b)
{
    return a->so && a->pcb && b->so && b->pcb && a->so==b->peer_so && b->so==a->peer_so
        && a->pcb==b->peer_pcb && b->pcb==a->peer_pcb;
}

static unsigned edges(const struct role_snapshot *a,const struct role_snapshot *b,struct endpoint *client,struct endpoint *server)
{
    unsigned count=0;
    for (unsigned i=0;i<a->count;i++) for (unsigned j=0;j<b->count;j++)
        if (reciprocal(&a->endpoints[i],&b->endpoints[j]))
        { *client=a->endpoints[i];*server=b->endpoints[j];count++; }
    return count;
}

static int same_endpoint(const struct endpoint *a,const struct endpoint *b)
{
    return a->fd==b->fd && a->so==b->so && a->pcb==b->pcb
        && a->peer_so==b->peer_so && a->peer_pcb==b->peer_pcb;
}

static int server_scope(pid_t pid,const char *prefix,const char *expected_executable)
{
    struct stat p,d;
    if (lstat(prefix,&p) || !S_ISDIR(p.st_mode) || p.st_uid!=getuid() || p.st_mode&0022) return 0;
    char dir[1024],resolved[1024],base[1024],parent[1024],expected[1024];
    if (!realpath("/tmp",base)) return 0;
    int parent_n=snprintf(parent,sizeof(parent),"%s/.wine-%u",base,getuid());
    struct stat parent_facts;
    if (parent_n<=0 || (size_t)parent_n>=sizeof(parent) || lstat(parent,&parent_facts)
        || !S_ISDIR(parent_facts.st_mode) || parent_facts.st_uid!=getuid() || parent_facts.st_mode&0077) return 0;
    int n=snprintf(dir,sizeof(dir),"/tmp/.wine-%u/server-%llx-%llx",getuid(),
                   (unsigned long long)p.st_dev,(unsigned long long)p.st_ino);
    int expected_n=snprintf(expected,sizeof(expected),"%s/server-%llx-%llx",parent,
                           (unsigned long long)p.st_dev,(unsigned long long)p.st_ino);
    if (n<=0 || (size_t)n>=sizeof(dir) || expected_n<=0 || (size_t)expected_n>=sizeof(expected)
        || !realpath(dir,resolved) || strcmp(resolved,expected) || lstat(expected,&d)
        || !S_ISDIR(d.st_mode) || d.st_uid!=getuid() || d.st_mode&0077) return 0;
    struct proc_vnodepathinfo cwd;
    memset(&cwd,0,sizeof(cwd));
    if (proc_pidinfo(pid,PROC_PIDVNODEPATHINFO,0,&cwd,sizeof(cwd))!=sizeof(cwd)) return 0;
    const struct vinfo_stat *v=&cwd.pvi_cdir.vip_vi.vi_stat;
    return memchr(cwd.pvi_cdir.vip_path,0,sizeof(cwd.pvi_cdir.vip_path))
        && !strcmp(cwd.pvi_cdir.vip_path,resolved) && v->vst_dev==(uint32_t)d.st_dev && v->vst_ino==d.st_ino
        && S_ISDIR(v->vst_mode) && executable(pid,expected_executable);
}

int main(int argc,char **argv)
{
    if (argc!=10) return unknown("invalid_arguments");
    int pids[3];uint64_t seconds[3],micros[3];char tail;
    for (int i=0;i<3;i++)
    {
        if (sscanf(argv[1+i*2],"%d%c",&pids[i],&tail)!=1 || pids[i]<=1
            || sscanf(argv[2+i*2],"%" SCNu64 ":%" SCNu64 "%c",&seconds[i],&micros[i],&tail)!=2
            || !seconds[i] || micros[i]>=1000000) return unknown("invalid_arguments");
        for (int j=0;j<i;j++) if (pids[i]==pids[j]) return unknown("invalid_arguments");
    }
    if (argv[7][0]!='/' || argv[8][0]!='/' || argv[9][0]!='/') return unknown("invalid_arguments");
    alarm(3);
    static struct role_snapshot before[3],after[3];
    for (int i=0;i<3;i++) if (!capture(pids[i],seconds[i],micros[i],&before[i])) return unknown("fd_snapshot_before");
    int scoped_before=server_scope(pids[2],argv[9],argv[8]) && executable(pids[0],argv[7]);
    struct endpoint gs={0},sg={0},ss={0},ss_peer={0},ags={0},asg={0},ass={0},ass_peer={0};
    unsigned game_edges=edges(&before[0],&before[2],&gs,&sg),steam_edges=edges(&before[1],&before[2],&ss,&ss_peer);
    for (int i=0;i<3;i++) if (!capture(pids[i],seconds[i],micros[i],&after[i])) return unknown("fd_snapshot_after");
    int scoped_after=server_scope(pids[2],argv[9],argv[8]) && executable(pids[0],argv[7]);
    unsigned after_game_edges=edges(&after[0],&after[2],&ags,&asg),after_steam_edges=edges(&after[1],&after[2],&ass,&ass_peer);
    int stable=1,complete=1;
    for (int i=0;i<3;i++)
    {
        if (!same_chain(&before[i].identity,&after[i].identity,1) || strcmp(before[i].executable,after[i].executable)) stable=0;
        if (!before[i].complete || !after[i].complete) complete=0;
    }
    int positive=scoped_before && scoped_after && stable && complete && game_edges==1 && steam_edges==1
        && after_game_edges==1 && after_steam_edges==1 && gs.so!=ss.so && sg.so!=ss_peer.so
        && same_endpoint(&gs,&ags) && same_endpoint(&sg,&asg) && same_endpoint(&ss,&ass) && same_endpoint(&ss_peer,&ass_peer);
    printf("{\"state\":\"%s\",\"stable\":%s,\"complete\":%s,\"serverScopeBefore\":%s,\"serverScopeAfter\":%s,"
           "\"gameEdgesBefore\":%u,\"gameEdgesAfter\":%u,\"steamEdgesBefore\":%u,\"steamEdgesAfter\":%u,\"roles\":[",
           positive?"PREFIX_CONNECTION_OBSERVED":"PREFIX_CONNECTION_UNKNOWN",stable?"true":"false",complete?"true":"false",
           scoped_before?"true":"false",scoped_after?"true":"false",game_edges,after_game_edges,steam_edges,after_steam_edges);
    for (int i=0;i<3;i++)
        printf("%s{\"role\":\"%s\",\"pid\":%d,\"birth\":\"%" PRIu64 ":%" PRIu64 "\",\"ppid\":%u,\"group\":%u,"
               "\"unixSocketsBefore\":%u,\"unixSocketsAfter\":%u,\"zeroHandlesBefore\":%u,\"zeroHandlesAfter\":%u}",
               i?",":"",i==0?"game":i==1?"steam":"server",pids[i],seconds[i],micros[i],before[i].identity.pbi_ppid,
               before[i].identity.pbi_pgid,before[i].count,after[i].count,before[i].zero_handles,after[i].zero_handles);
    printf("]}\n");return 0;
}
