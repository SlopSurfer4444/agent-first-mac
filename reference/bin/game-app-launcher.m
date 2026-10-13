/* Finder entrypoint only. Routes and arguments are compiled, never read from
 * bundle metadata or passed through from Finder. Existing launchers own games. */
#import <AppKit/AppKit.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#ifndef GAME_ROUTE
#error GAME_ROUTE is required
#endif
static NSString *launchFailure(NSData *output, BOOL overflow) {
#if GAME_ROUTE == 1
    NSString *name = @"Counter-Strike 2";
#elif GAME_ROUTE == 2
    NSString *name = @"Ubisoft Connect";
#elif GAME_ROUTE == 3
    NSString *name = @"Steam";
#else
    NSString *name = @"Dark Souls III";
#endif
    if (!overflow && output.length <= 4096) {
        id record = [NSJSONSerialization JSONObjectWithData:output options:0 error:NULL];
        if ([record isKindOfClass:[NSDictionary class]] &&
            ([record[@"state"] isEqual:@"BLOCKED"] || [record[@"state"] isEqual:@"blocked"]) &&
            [record[@"reason"] isKindOfClass:[NSString class]]) {
            NSString *reason = record[@"reason"];
            if ([reason isEqualToString:@"foreign_steam_active"])
                return [NSString stringWithFormat:@"Открыт Steam в другой игровой среде. Закройте Steam и Ubisoft Connect перед запуском %@.", name];
            if ([reason isEqualToString:@"profile_active"] || [reason isEqualToString:@"session_active"])
                return [NSString stringWithFormat:@"Игровая сессия или её служебные процессы ещё работают. Завершите Steam и Ubisoft Connect, дождитесь закрытия игры, затем повторите запуск %@.", name];
            if ([reason isEqualToString:@"launcher_busy"])
                return [NSString stringWithFormat:@"Другой запуск или обслуживание игровой среды уже выполняется. Дождитесь завершения перед запуском %@.", name];
#if GAME_ROUTE == 2
            if ([reason isEqualToString:@"vpn_proxy_unavailable"])
                return @"Включите VPN и повторите запуск Ubisoft Connect: локальный прокси недоступен.";
#endif
            if ([reason isEqualToString:@"launch_in_progress"])
                return [NSString stringWithFormat:@"Запуск %@ ещё выполняется. Повторный запрос не отправлен; дождитесь открытия клиента или игры.", name];
            if ([reason isEqualToString:@"pending_launch_unconfirmed"])
                return [NSString stringWithFormat:@"Предыдущий запуск %@ не подтверждён. Закройте игровые клиенты; требуется проверка восстановления запуска.", name];
            NSSet *integrity = [NSSet setWithArray:@[@"hub_owner_mismatch", @"manifest_identity", @"manifest_changed", @"launcher_changed", @"runtime_changed", @"runtime_not_owned", @"prefix_not_owned", @"unsafe_directory", @"unsafe_file", @"unsafe_launch_log", @"unsafe_private_file", @"unsafe_steam_directory", @"prefix_not_private"]];
            if ([integrity containsObject:reason])
                return [NSString stringWithFormat:@"Проверка игровой среды %@ не пройдена. Требуется восстановить проверенный запуск; повторное открытие не исправит эту ошибку.", name];
        }
    }
#if GAME_ROUTE == 2
    return @"Не удалось открыть Ubisoft Connect. Проверьте VPN и состояние игровой среды, затем повторите запуск.";
#else
    return [NSString stringWithFormat:@"Не удалось запустить %@. Проверьте состояние игровой среды и повторите запуск.", name];
#endif
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        struct passwd *owner = getpwuid(getuid());
        if (!owner || !owner->pw_dir) return 1;
        NSString *home = [NSString stringWithUTF8String:owner->pw_dir];
#if GAME_ROUTE == 1
        NSString *resolver = @"games-play", *argument = @"cs2";
#elif GAME_ROUTE == 2
        NSString *resolver = @"games-play", *argument = @"prince";
#elif GAME_ROUTE == 3
        NSString *resolver = @"games-play", *argument = @"steam";
#elif GAME_ROUTE == 4
        NSString *resolver = @"ds3-play", *argument = @"play";
#else
#error Unknown GAME_ROUTE
#endif
        if (argc == 2 && strcmp(argv[1], "--check-route") == 0) {
            printf("%s %s\n", resolver.UTF8String, argument.UTF8String);
            return 0;
        }
        if (argc == 2 && strcmp(argv[1], "--check-error") == 0) {
            NSData *fixture = [[NSFileHandle fileHandleWithStandardInput] readDataOfLength:4097];
            printf("%s\n", launchFailure(fixture, fixture.length > 4096).UTF8String);
            return 0;
        }
        NSTask *task = [[NSTask alloc] init];
        task.executableURL = [NSURL fileURLWithPath:[[home stringByAppendingPathComponent:@"AIDev/bin"] stringByAppendingPathComponent:resolver]];
        task.arguments = @[argument];
        task.environment = @{@"HOME":home, @"PATH":@"/usr/bin:/bin:/usr/sbin:/sbin", @"LANG":@"en_US.UTF-8"};
        task.currentDirectoryURL = [NSURL fileURLWithPath:home];
        task.standardInput = [NSFileHandle fileHandleWithNullDevice];
        /* Resolver output is diagnostic data, never a shell command or GUI text. */
        NSPipe *outputPipe = [NSPipe pipe];
        task.standardOutput = outputPipe;
        task.standardError = [NSFileHandle fileHandleWithNullDevice];
        NSError *error = nil;
        BOOL launched = [task launchAndReturnError:&error];
        NSMutableData *output = [NSMutableData data];
        BOOL overflow = NO;
        if (launched) {
            [outputPipe.fileHandleForWriting closeFile];
            for (;;) {
                NSData *chunk = [outputPipe.fileHandleForReading readDataOfLength:4096];
                if (chunk.length == 0) break;
                if (!overflow && output.length + chunk.length <= 4096) [output appendData:chunk];
                else { overflow = YES; [output setLength:0]; }
            }
            [task waitUntilExit];
        }
        if (!launched || task.terminationStatus != 0) {
            [NSApplication sharedApplication];
            [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
            [NSApp activateIgnoringOtherApps:YES];
            NSAlert *alert = [[NSAlert alloc] init];
            alert.messageText = @"Не удалось запустить игру";
            alert.informativeText = launchFailure(output, overflow);
            [alert addButtonWithTitle:@"OK"];
            [alert runModal];
            return 1;
        }
        return 0;
    }
}
