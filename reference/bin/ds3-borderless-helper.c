/* Offline DS3-only borderless helper. No injection, display-mode or DXGI calls. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <stdlib.h>

typedef struct { DWORD pid,tid; HANDLE process; HWND window; RECT rect,client,monitor; DWORD style,ex; } Target;
static volatile LONG64 deadline;
#ifdef SELFTEST
static int fixture_target;
static volatile LONG fixture_stop,fixture_reapplied;
#endif
static void arm(void) { InterlockedExchange64(&deadline,(LONG64)GetTickCount64()+5000); }
static void disarm(void) { InterlockedExchange64(&deadline,0); }
static DWORD WINAPI watchdog(void *unused) {
    (void)unused;
    for (;;) { LONG64 until=InterlockedCompareExchange64(&deadline,0,0);
        if (until && (LONG64)GetTickCount64()>=until) {
            puts("{\"state\":\"UNKNOWN\",\"reason\":\"synchronous_api_timeout\"}");fflush(stdout);ExitProcess(4);
        } Sleep(50);
    }
}
static int image_ok(const WCHAR *name) {
    const WCHAR suffix[]=L"\\Game\\DarkSoulsIII.exe";
    size_t n=wcslen(name),s=wcslen(suffix);
    return n>s && !_wcsicmp(name+n-s,suffix);
}
static int process_ok(const Target *t) {
    WCHAR path[32768];DWORD size=32768;
    if (!t->process || WaitForSingleObject(t->process,0)!=WAIT_TIMEOUT) return 0;
#ifdef SELFTEST
    if (fixture_target) return t->pid==GetCurrentProcessId();
#endif
    return QueryFullProcessImageNameW(t->process,0,path,&size) && image_ok(path);
}
static int binding_ok(const Target *t) {
    DWORD pid=0;DWORD tid=GetWindowThreadProcessId(t->window,&pid);
    return process_ok(t) && pid==t->pid && tid==t->tid && IsWindow(t->window) && IsWindowVisible(t->window)
        && !IsIconic(t->window) && GetAncestor(t->window,GA_ROOT)==t->window && !GetWindow(t->window,GW_OWNER);
}
static int read_long(HWND h,int index,DWORD *value) {
    SetLastError(0);LONG_PTR result=GetWindowLongPtrW(h,index);
    if (!result && GetLastError()) return 0;*value=(DWORD)result;return 1;
}
static int write_long(HWND h,int index,DWORD value) {
    SetLastError(0);LONG_PTR result=SetWindowLongPtrW(h,index,(LONG_PTR)value);
    return result || !GetLastError();
}
typedef struct { DWORD pid;HWND window;DWORD tid;unsigned count,seen;int invalid; } Scan;
static BOOL CALLBACK enum_window(HWND h,LPARAM data) {
    Scan *s=(Scan *)data;DWORD pid=0;DWORD tid=GetWindowThreadProcessId(h,&pid);DWORD style;
    if (++s->seen>4096) { s->invalid=1;return FALSE; }
    if (pid!=s->pid || !IsWindowVisible(h) || IsIconic(h) || GetWindow(h,GW_OWNER) || GetAncestor(h,GA_ROOT)!=h) return TRUE;
    if (!read_long(h,GWL_STYLE,&style)) { s->invalid=1;return FALSE; }
    if (style&WS_CHILD) return TRUE;
    s->count++;s->window=h;s->tid=tid;return TRUE;
}
static int capture_safe(void) {
    const WCHAR *keys[]={L"Software\\Wine\\Mac Driver",L"Software\\Wine\\AppDefaults\\DarkSoulsIII.exe\\Mac Driver"};
    for (unsigned i=0;i<2;i++) {
        HKEY key;LONG error=RegOpenKeyExW(HKEY_CURRENT_USER,keys[i],0,KEY_QUERY_VALUE,&key);
        if (error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND) continue;
        if (error!=ERROR_SUCCESS) return 0;
        WCHAR value[32]={0};DWORD bytes=sizeof(value),type=0;
        error=RegQueryValueExW(key,L"CaptureDisplaysForFullscreen",0,&type,(BYTE *)value,&bytes);RegCloseKey(key);
        if (error==ERROR_FILE_NOT_FOUND) continue;
        if (error!=ERROR_SUCCESS || type!=REG_SZ || bytes<sizeof(WCHAR) || bytes>sizeof(value) || bytes%sizeof(WCHAR) || value[bytes/sizeof(WCHAR)-1]) return 0;
        WCHAR first=value[0];if (first==L'Y'||first==L'y'||first==L'T'||first==L't'||first==L'1') return 0;
        if (first && first!=L'N' && first!=L'n' && first!=L'F' && first!=L'f' && first!=L'0') return 0;
    } return 1;
}
static int snapshot(Target *t) {
    MONITORINFO monitor={0};monitor.cbSize=sizeof(monitor);
    return binding_ok(t) && read_long(t->window,GWL_STYLE,&t->style) && read_long(t->window,GWL_EXSTYLE,&t->ex)
        && !(t->style&(WS_CHILD|WS_MINIMIZE|WS_MAXIMIZE)) && GetWindowRect(t->window,&t->rect)
        && GetClientRect(t->window,&t->client) && GetMonitorInfoW(MonitorFromWindow(t->window,MONITOR_DEFAULTTONEAREST),&monitor)
        && (t->monitor=monitor.rcMonitor,t->monitor.right>t->monitor.left && t->monitor.bottom>t->monitor.top)
        && t->monitor.right-t->monitor.left<=16384 && t->monitor.bottom-t->monitor.top<=16384;
}
/* Returns 0 unique bound target, 2 absent, 3 ambiguous/invalid. */
static int select_target(Target *t) {
    HANDLE list=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);PROCESSENTRY32W entry={0};entry.dwSize=sizeof(entry);unsigned count=0,seen=0;DWORD pid=0;
    if (list==INVALID_HANDLE_VALUE) return 3;
    if (Process32FirstW(list,&entry)) do {
        if (++seen>8192) { CloseHandle(list);return 3; }
        if (!_wcsicmp(entry.szExeFile,L"DarkSoulsIII.exe")) { pid=entry.th32ProcessID;count++; }
    } while (Process32NextW(list,&entry));
    CloseHandle(list);if (!count) return 2;if (count!=1) return 3;
    memset(t,0,sizeof(*t));t->pid=pid;t->process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);
    if (!t->process) return GetLastError()==ERROR_INVALID_PARAMETER?2:3;
    if (!process_ok(t)) { CloseHandle(t->process);t->process=0;return 3; }
    Scan scan={0};scan.pid=pid;
    if (!EnumWindows(enum_window,(LPARAM)&scan) || scan.invalid || scan.count>1) { CloseHandle(t->process);t->process=0;return 3; }
    if (!scan.count) { CloseHandle(t->process);t->process=0;return 2; }
    t->window=scan.window;t->tid=scan.tid;
    if (!snapshot(t)) { CloseHandle(t->process);t->process=0;return 3; } return 0;
}
static int matches(const Target *t,DWORD style,DWORD ex,const RECT *rect) {
    RECT current;DWORD s,e;
    return binding_ok(t) && read_long(t->window,GWL_STYLE,&s) && read_long(t->window,GWL_EXSTYLE,&e)
        && s==style && e==ex && GetWindowRect(t->window,&current) && EqualRect(&current,rect);
}
static int wait_match(const Target *t,DWORD style,DWORD ex,const RECT *rect) {
    ULONGLONG end=GetTickCount64()+2000;
    do { if (matches(t,style,ex,rect)) return 1;Sleep(25); } while (GetTickCount64()<end);
    return 0;
}
static int restore(const Target *t) {
    if (!binding_ok(t)) return 0;
    if (!write_long(t->window,GWL_STYLE,t->style) || !write_long(t->window,GWL_EXSTYLE,t->ex)) return 0;
    if (!SetWindowPos(t->window,(t->ex&WS_EX_TOPMOST)?HWND_TOPMOST:HWND_NOTOPMOST,t->rect.left,t->rect.top,t->rect.right-t->rect.left,t->rect.bottom-t->rect.top,SWP_FRAMECHANGED|SWP_NOACTIVATE|SWP_ASYNCWINDOWPOS)) return 0;
    return wait_match(t,t->style,t->ex,&t->rect);
}
static int apply(const Target *t) {
    DWORD style=(t->style&~WS_OVERLAPPEDWINDOW)|WS_POPUP;
    DWORD ex=t->ex&~(WS_EX_WINDOWEDGE|WS_EX_CLIENTEDGE|WS_EX_DLGMODALFRAME|WS_EX_STATICEDGE);
    if (!binding_ok(t) || !matches(t,t->style,t->ex,&t->rect)) return 3;
    if (write_long(t->window,GWL_STYLE,style) && binding_ok(t) && write_long(t->window,GWL_EXSTYLE,ex)
        && SetWindowPos(t->window,HWND_TOPMOST,t->monitor.left,t->monitor.top,t->monitor.right-t->monitor.left,t->monitor.bottom-t->monitor.top,SWP_FRAMECHANGED|SWP_NOACTIVATE|SWP_ASYNCWINDOWPOS)
        && wait_match(t,style,ex|WS_EX_TOPMOST,&t->monitor)) return 0;
    int restored=restore(t);printf("{\"state\":\"FAILED\",\"rollbackVerified\":%s}\n",restored?"true":"false");return 4;
}
static int report(const char *state,const Target *t) {
    RECT rect,client;DWORD style,ex;
    if (!binding_ok(t) || !GetWindowRect(t->window,&rect) || !GetClientRect(t->window,&client) || !read_long(t->window,GWL_STYLE,&style) || !read_long(t->window,GWL_EXSTYLE,&ex)) { puts("{\"state\":\"UNKNOWN\",\"reason\":\"post_observation_failed\"}");return 0; }
    printf("{\"state\":\"%s\",\"rect\":[%ld,%ld,%ld,%ld],\"width\":%ld,\"height\":%ld,\"clientWidth\":%ld,\"clientHeight\":%ld,\"style\":%lu,\"exStyle\":%lu}\n",state,rect.left,rect.top,rect.right,rect.bottom,rect.right-rect.left,rect.bottom-rect.top,client.right-client.left,client.bottom-client.top,(unsigned long)style,(unsigned long)ex);return 1;
}
/* Follow only the retained process handle; never select a later game PID. */
static int follow(Target *t) {
    ULONGLONG until=GetTickCount64()+12ULL*60*60*1000;
    RECT previous={0}; HWND previous_window=NULL; DWORD previous_style=0,previous_ex=0;
    while (GetTickCount64()<until) {
#ifdef SELFTEST
        if (fixture_target) {
            MSG msg;while (PeekMessageW(&msg,NULL,0,0,PM_REMOVE)) { TranslateMessage(&msg);DispatchMessageW(&msg); }
            if (fixture_stop) return fixture_reapplied?0:4;
        }
#endif
        if (WaitForSingleObject(t->process,500)!=WAIT_TIMEOUT) {
            puts("{\"state\":\"GAME_EXITED\"}");return 0;
        }
        arm();
        if (!process_ok(t) || !capture_safe()) { disarm();return 3; }
        Scan scan={0};scan.pid=t->pid;
        if (!EnumWindows(enum_window,(LPARAM)&scan) || scan.invalid || scan.count>1) { disarm();return 3; }
        /* Minimized/hidden or unfocused game: leave it alone, including topmost. */
        if (!scan.count || GetForegroundWindow()!=scan.window) { previous_window=NULL;disarm();continue; }
        t->window=scan.window;t->tid=scan.tid;
        if (!snapshot(t)) { disarm();return 3; }
        DWORD style=(t->style&~WS_OVERLAPPEDWINDOW)|WS_POPUP;
        DWORD ex=(t->ex&~(WS_EX_WINDOWEDGE|WS_EX_CLIENTEDGE|WS_EX_DLGMODALFRAME|WS_EX_STATICEDGE))|WS_EX_TOPMOST;
        if (matches(t,style,ex,&t->monitor)) { previous_window=NULL;disarm();continue; }
        /* Two equal observations avoid racing the resolution menu's resize. */
        int stable=previous_window==t->window && EqualRect(&previous,&t->rect)
            && previous_style==t->style && previous_ex==t->ex;
        previous=t->rect;previous_window=t->window;previous_style=t->style;previous_ex=t->ex;
        if (stable) {
            int result=apply(t);previous_window=NULL;
            if (result || !report("REAPPLIED",t)) { disarm();return result?result:4; }
            fflush(stdout);
#ifdef SELFTEST
            if (fixture_target) InterlockedIncrement(&fixture_reapplied);
#endif
        }
        disarm();
    }
    puts("{\"state\":\"SESSION_LIMIT\"}");return 0;
}
#ifdef SELFTEST
static DWORD WINAPI fixture_changes(void *data) {
    HWND h=(HWND)data;Sleep(700);
    SetWindowPos(h,NULL,90,110,960,540,SWP_NOZORDER|SWP_NOACTIVATE);
    Sleep(2200);InterlockedExchange(&fixture_stop,1);return 0;
}
static int selftest(void) {
    if (!image_ok(L"C:\\games\\Game\\DarkSoulsIII.exe") || image_ok(L"C:\\games\\DarkSoulsIII.exe") || image_ok(L"C:\\games\\Game\\Other.exe")) return 3;
    WNDCLASSW cls={0};cls.lpfnWndProc=DefWindowProcW;cls.hInstance=GetModuleHandleW(NULL);cls.lpszClassName=L"DS3OwnedBorderlessFixture";
    if (!RegisterClassW(&cls)) return 3;
    HWND h=CreateWindowExW(0,cls.lpszClassName,L"Owned offline fixture",WS_OVERLAPPEDWINDOW,60,100,800,600,NULL,NULL,cls.hInstance,NULL);
    if (!h) return 3;ShowWindow(h,SW_SHOWNOACTIVATE);fixture_target=1;
    Target t={0};t.pid=GetCurrentProcessId();t.tid=GetWindowThreadProcessId(h,NULL);t.window=h;t.process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,t.pid);
    if (!snapshot(&t)) return 3;
    Target wrong=t;wrong.pid++;if (binding_ok(&wrong)) return 3;wrong=t;wrong.window=GetDesktopWindow();if (binding_ok(&wrong)) return 3;
    t.monitor=(RECT){80,120,720,480};arm();int changed=apply(&t);int reverted=changed==0 && restore(&t);
    int resized=0,minimized=0;
    if (reverted && SetWindowPos(h,NULL,90,110,960,540,SWP_NOZORDER|SWP_NOACTIVATE) && snapshot(&t)) {
        t.monitor=(RECT){80,120,720,480};resized=apply(&t)==0 && restore(&t);
    }
    ShowWindow(h,SW_MINIMIZE);minimized=!binding_ok(&t);
    disarm();ShowWindow(h,SW_RESTORE);SetForegroundWindow(h);
    HANDLE changes=CreateThread(NULL,0,fixture_changes,h,0,NULL);
    int followed=changes && follow(&t)==0;
    if (changes) { WaitForSingleObject(changes,4000);CloseHandle(changes); }
    DestroyWindow(h);CloseHandle(t.process);
    printf("{\"state\":\"SELFTEST\",\"identityRefusal\":true,\"ownedWindowApply\":%s,\"restoreVerified\":%s}\n",changed==0?"true":"false",reverted?"true":"false");return reverted && resized && minimized && followed?0:4;
}
#endif
int main(int argc,char **argv) {
    int applying=0,following=0;unsigned seconds=180;
#ifdef SELFTEST
    if (argc==2 && !strcmp(argv[1],"--selftest")) { HANDLE watch=CreateThread(NULL,0,watchdog,NULL,0,NULL);if (!watch) return 3;CloseHandle(watch);arm();return selftest(); }
#endif
    if (argc==2 && !strcmp(argv[1],"--probe")) applying=0;
    else if ((argc==2 || argc==4) && (!strcmp(argv[1],"--apply") || !strcmp(argv[1],"--follow"))) {
        following=!strcmp(argv[1],"--follow");
        applying=1;if (argc==4) { if (strcmp(argv[2],"--wait") || !*argv[3]) return 3;char *end;unsigned long value=strtoul(argv[3],&end,10);if (*end || value>(following?900:180)) return 3;seconds=(unsigned)value; }
    } else { puts("{\"state\":\"REFUSED\",\"reason\":\"usage\"}");return 3; }
    HANDLE watch=CreateThread(NULL,0,watchdog,NULL,0,NULL);if (!watch) return 3;CloseHandle(watch);
    arm();if (applying && !capture_safe()) { puts("{\"state\":\"REFUSED\",\"reason\":\"display_capture_policy\"}");return 3; }disarm();
    Target t;ULONGLONG until=GetTickCount64()+(ULONGLONG)seconds*1000;int selected;
    do { arm();selected=select_target(&t);disarm();if (!selected || !applying || (!following && selected!=2) || GetTickCount64()>=until) break;Sleep(250); } while (1);
    if (selected) { printf("{\"state\":\"%s\",\"reason\":\"target_selection\"}\n",selected==2?"NOT_FOUND":"REFUSED");return selected; }
    arm();if (applying && !capture_safe()) { puts("{\"state\":\"REFUSED\",\"reason\":\"display_capture_policy\"}");disarm();CloseHandle(t.process);return 3; }
    int result=applying?apply(&t):0;if (!result && !report(applying?"APPLIED":"PROBE",&t)) result=4;else if (result==3) puts("{\"state\":\"REFUSED\",\"reason\":\"target_changed\"}");disarm();fflush(stdout);if (!result && following) result=follow(&t);CloseHandle(t.process);return result;
}
