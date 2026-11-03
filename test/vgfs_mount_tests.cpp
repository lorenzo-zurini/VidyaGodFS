// vgfs_mount_tests — the REAL vidyagodfs binary on a REAL FUSE mount, for what only a mount can show: the
// --watch-pid lifecycle. A mount must never outlive the process that asked for it, however that process ends.
//
// The suite makes itself a child subreaper, so everything the helper leaves behind (the daemonized server, any
// helper process of its own) is reparented HERE rather than to init: "the mount is gone and every process it
// started has exited" is then something the test can wait for and see, not infer.
//
// Usage: vgfs_mount_tests <path to vidyagodfs>. Exits 77 (ctest SKIP) where FUSE cannot be mounted at all.

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;

// ---- tiny harness (as vgfs_tests) -------------------------------------------
namespace {
int g_fail = 0, g_checks = 0;
#define CHECK(cond) do { ++g_checks; if (!(cond)) { \
    std::cerr << "  FAIL " << __FILE__ << ":" << __LINE__ << "  " #cond "\n"; ++g_fail; } } while (0)
std::vector<std::pair<std::string, std::function<void()>>> g_tests;
struct Reg { Reg(const char *n, std::function<void()> f) { g_tests.push_back({ n, std::move(f) }); } };
std::string g_helper;
} // namespace
#define TEST(name) static void name(); static Reg reg_##name(#name, name); static void name()

// ---- fixture ----------------------------------------------------------------
// Is `mp` in this namespace's mount table? Read from mountinfo, never stat(): a stat on a FUSE mountpoint is a
// request to its server, and the server is the thing under test.
static bool Mounted(const fs::path &mp)
{
    std::ifstream In("/proc/self/mountinfo");
    std::string Line;
    while (std::getline(In, Line))
    {
        // id parent major:minor root MOUNTPOINT ...
        size_t P = 0;
        for (int F = 0; F < 4 && P != std::string::npos; ++F) P = Line.find(' ', P + 1);
        if (P == std::string::npos) continue;
        const size_t E = Line.find(' ', P + 1);
        if (Line.substr(P + 1, E - P - 1) == mp.string()) return true;
    }
    return false;
}

struct Fixture {
    fs::path root, mp, spec;
    Fixture() {
        root = fs::temp_directory_path() / ("vgfs_mount_" + std::to_string(::getpid()) + "_" + std::to_string(++n));
        mp = root / "mnt"; spec = root / "spec.json";
        fs::create_directories(root / "layer");
        fs::create_directories(mp);
        std::ofstream(root / "layer" / "a.txt") << "hi";
        std::ofstream(spec) << "{\"mountpoint\":\"" << mp.string() << "\",\"readonly\":true,\"layers\":["
                            << "{\"type\":\"dir\",\"source\":\"" << (root / "layer").string() << "\",\"target\":\"\"}]}";
    }
    // A failing run leaves the mount up by definition; take it down so one red test does not leak into the next.
    ~Fixture() {
        if (Mounted(mp)) { std::cerr << "    (test left " << mp << " mounted; unmounting)\n"; RunWait({ "fusermount3", "-u", "-z", mp.string() }); }
        ReapAll(std::chrono::seconds(5), true);
        std::error_code Ec; fs::remove_all(root, Ec);
    }
    static int RunWait(const std::vector<std::string> &Argv) {
        pid_t P = fork();
        if (P == 0) {
            std::vector<char *> A; for (const auto &S : Argv) A.push_back(const_cast<char *>(S.c_str())); A.push_back(nullptr);
            execvp(A[0], A.data()); _exit(127);
        }
        int St = 0; waitpid(P, &St, 0); return St;
    }
    // Reap every descendant (we are their subreaper) until none is left or `limit` passes. With `kill`, whatever
    // is still alive at the limit is SIGKILLed first. Returns true when all of them exited within the limit.
    static bool ReapAll(std::chrono::milliseconds limit, bool kill = false) {
        const auto End = std::chrono::steady_clock::now() + limit;
        for (;;) {
            pid_t R = waitpid(-1, nullptr, WNOHANG);
            if (R < 0 && errno == ECHILD) return true;
            if (R > 0) continue;
            if (std::chrono::steady_clock::now() >= End) {
                if (kill) { KillDescendants(); while (waitpid(-1, nullptr, 0) > 0) {} }
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    static void KillDescendants() {
        for (const auto &E : fs::directory_iterator("/proc")) {
            std::ifstream S(E.path() / "stat"); std::string Pid, Comm, State; pid_t PPid = 0;
            if (!(S >> Pid >> Comm >> State >> PPid)) continue;
            if (PPid == ::getpid()) ::kill((pid_t)std::stoi(Pid), SIGKILL);
        }
    }
    // Waits up to `limit` for the mount to be gone AND every process it involved to have exited.
    bool TornDown(std::chrono::milliseconds limit) {
        const auto End = std::chrono::steady_clock::now() + limit;
        while (Mounted(mp) && std::chrono::steady_clock::now() < End) std::this_thread::sleep_for(std::chrono::milliseconds(20));
        if (Mounted(mp)) return false;
        return ReapAll(std::chrono::duration_cast<std::chrono::milliseconds>(End - std::chrono::steady_clock::now()));
    }
    static inline int n = 0;
};

// Forks a SPAWNER the way VidyaGod is one: it runs the helper with --watch-pid <itself> and blocks until the
// helper's launch returns (fuse daemonizes: the launch returns once the mount is live). The spawner is put in
// its own process group, as a shell job or a test runner's child is. It then reports the helper's exit status
// on `ready` and either exits (`exitAfter`) or waits to be killed. Returns the spawner's pid.
static pid_t StartSpawner(const Fixture &F, bool exitAfter, int ready)
{
    pid_t S = fork();
    if (S != 0) return S;
    setpgid(0, 0);
    pid_t H = fork();
    if (H == 0) {
        execl(g_helper.c_str(), "vidyagodfs", F.spec.c_str(), F.mp.c_str(),
              "--watch-pid", std::to_string(getppid()).c_str(), "-o", "auto_cache", (char *)nullptr);
        _exit(127);
    }
    int St = 0; waitpid(H, &St, 0);
    const char Ok = (WIFEXITED(St) && WEXITSTATUS(St) == 0) ? 1 : 0;
    if (write(ready, &Ok, 1) != 1) _exit(1);
    if (exitAfter) _exit(0);
    for (;;) pause();
}

static bool MountedBySpawner(Fixture &F, pid_t &Spawner, bool exitAfter)
{
    int P[2]; if (pipe(P) != 0) return false;
    Spawner = StartSpawner(F, exitAfter, P[1]);
    close(P[1]);
    char Ok = 0; const bool Got = read(P[0], &Ok, 1) == 1; close(P[0]);
    return Got && Ok == 1 && Mounted(F.mp);
}

// ---- tests ------------------------------------------------------------------

// While the spawner lives the mount stays: the watch waits for the spawner, it does not take the mount down on
// its own. A second of steady reads is ample — an unmount needs a few milliseconds.
TEST(a_living_spawner_keeps_its_mount) {
    Fixture F; pid_t S = 0;
    CHECK(MountedBySpawner(F, S, false));
    bool Steady = true;
    for (int I = 0; I < 50 && Steady; ++I) {
        std::ifstream In(F.mp / "a.txt"); std::string Got; In >> Got;
        Steady = Got == "hi" && Mounted(F.mp);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    CHECK(Steady);
    CHECK(::kill(-S, SIGKILL) == 0);
    waitpid(S, nullptr, 0);
    CHECK(F.TornDown(std::chrono::seconds(10)));
}

// The spawner simply exits (and is reaped): the mount goes, and the helper with it.
TEST(a_spawner_that_exits_takes_its_mount_with_it) {
    Fixture F; pid_t S = 0;
    CHECK(MountedBySpawner(F, S, true));
    waitpid(S, nullptr, 0);
    CHECK(F.TornDown(std::chrono::seconds(10)));
}

// The spawner has exited but its parent has not reaped it YET. It is dead — it will never unmount anything — but
// its pid still answers kill(pid, 0) as a zombie, so a liveness probe by pid reads it as running for as long as
// the parent lets it lie (here: until the mount is gone, i.e. forever).
TEST(a_spawner_that_exits_unreaped_takes_its_mount_with_it) {
    Fixture F; pid_t S = 0;
    CHECK(MountedBySpawner(F, S, true));
    CHECK(F.TornDown(std::chrono::seconds(10)));
}

// The spawner is killed TOGETHER WITH ITS PROCESS GROUP — what a test runner's timeout, a Ctrl-C in the terminal
// or a `kill -- -pgid` does. Everything the helper left in that group dies with it; a watcher that lived there
// died before it could see its spawner go, and the mount stayed up for hours with nothing left to take it down.
TEST(a_spawner_killed_with_its_process_group_takes_its_mount_with_it) {
    Fixture F; pid_t S = 0;
    CHECK(MountedBySpawner(F, S, false));
    CHECK(::kill(-S, SIGKILL) == 0);
    waitpid(S, nullptr, 0);
    CHECK(F.TornDown(std::chrono::seconds(10)));
}

// The same for a hangup — the signal a closed terminal sends its whole foreground group.
TEST(a_spawner_hung_up_with_its_process_group_takes_its_mount_with_it) {
    Fixture F; pid_t S = 0;
    CHECK(MountedBySpawner(F, S, false));
    CHECK(::kill(-S, SIGHUP) == 0);
    waitpid(S, nullptr, 0);
    CHECK(F.TornDown(std::chrono::seconds(10)));
}

// The spawner dies while a game it started — now orphaned, outside its group — still holds a file open in the
// mount. The mount must leave the table at once anyway (a plain unmount refuses a busy mount and would leave it
// up), while the open file keeps working until the game lets go; only then does the server end.
TEST(a_file_held_open_does_not_keep_the_mount_up_and_still_reads) {
    Fixture F; pid_t S = 0;
    CHECK(MountedBySpawner(F, S, false));
    const int Fd = open((F.mp / "a.txt").c_str(), O_RDONLY);
    CHECK(Fd >= 0);
    CHECK(::kill(-S, SIGKILL) == 0);
    waitpid(S, nullptr, 0);
    const auto End = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (Mounted(F.mp) && std::chrono::steady_clock::now() < End) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CHECK(!Mounted(F.mp));
    char Buf[8] = {};
    CHECK(pread(Fd, Buf, sizeof Buf, 0) == 2 && std::string(Buf, 2) == "hi");
    if (Fd >= 0) close(Fd);
    CHECK(F.TornDown(std::chrono::seconds(10)));
}

// A spawner that is already gone when the helper starts gets no mount at all: nothing would ever take it down.
TEST(a_spawner_already_gone_gets_no_mount) {
    Fixture F;
    pid_t Dead = fork();
    if (Dead == 0) _exit(0);
    waitpid(Dead, nullptr, 0);
    const int St = Fixture::RunWait({ g_helper, F.spec.string(), F.mp.string(), "--watch-pid", std::to_string(Dead) });
    CHECK(!(WIFEXITED(St) && WEXITSTATUS(St) == 0));
    CHECK(!Mounted(F.mp));
    CHECK(Fixture::ReapAll(std::chrono::seconds(10)));
}

int main(int argc, char **argv)
{
    if (argc < 2) { std::cerr << "usage: vgfs_mount_tests <path to vidyagodfs>\n"; return 2; }
    g_helper = argv[1];
    // FUSE needs the device and the setuid mount helper; a container without them cannot run this suite at all.
    const int Dev = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (Dev < 0 || Fixture::RunWait({ "fusermount3", "--version" }) != 0) {
        std::cerr << "SKIP: FUSE is not available here (/dev/fuse or fusermount3)\n";
        return 77;
    }
    close(Dev);
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) { std::cerr << "cannot become a subreaper\n"; return 1; }

    for (auto &[Name, Fn] : g_tests) {
        const int Before = g_fail;
        Fn();
        std::cout << (g_fail == Before ? "[ OK ] " : "[FAIL] ") << Name << "\n";
    }
    std::cout << g_checks << " checks, " << g_fail << " failed\n";
    return g_fail ? 1 : 0;
}
