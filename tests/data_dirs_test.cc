#include "libpstack/context.h"

#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>

using Paths = std::vector<std::filesystem::path>;

std::optional<std::string>
environment(const char *name)
{
    const char *value = getenv(name);
    return value ? std::optional<std::string>(value) : std::nullopt;
}

void
check(const char *name, Paths expected)
{
    static const Paths executablePaths = []() -> Paths {
        const auto executableDir =
            std::filesystem::read_symlink("/proc/self/exe").parent_path();
        return {
            executableDir.parent_path() / "share" / "pstack",
            executableDir / "pstack",
            executableDir,
        };
    }();
    expected.insert(expected.end(), executablePaths.begin(), executablePaths.end());
    const auto dataHome = environment("XDG_DATA_HOME");
    const auto dataDirs = environment("XDG_DATA_DIRS");
    const auto actual = pstack::findXdgDataDirs();
    if (actual != expected || dataHome != environment("XDG_DATA_HOME") ||
        dataDirs != environment("XDG_DATA_DIRS")) {
        std::cerr << name << ": unexpected data search paths or environment change\n";
        std::cerr << "expected:\n";
        for (const auto &path : expected)
            std::cerr << path << '\n';
        std::cerr << "actual:\n";
        for (const auto &path : actual)
            std::cerr << path << '\n';
        std::exit(1);
    }
}

int
main()
{
    setenv("XDG_DATA_HOME", "/test/user-data", 1);
    setenv("XDG_DATA_DIRS", ":/test/system-one::/test/system-two:", 1);
    check("configured XDG_DATA_DIRS", {
        ".",
        "/test/user-data/pstack",
        "/test/system-one/pstack",
        "/test/system-two/pstack",
    });

    setenv("XDG_DATA_DIRS", "", 1);
    const Paths defaults{
        ".",
        "/test/user-data/pstack",
        "/usr/local/share/pstack",
        "/usr/share/pstack",
    };
    check("empty XDG_DATA_DIRS", defaults);
    unsetenv("XDG_DATA_DIRS");
    check("unset XDG_DATA_DIRS", defaults);

    setenv("XDG_DATA_DIRS", ":", 1);
    check("empty XDG_DATA_DIRS entries", {".", "/test/user-data/pstack"});

    const auto home = environment("HOME");
    const auto userDefault = home && !home->empty()
        ? std::filesystem::path(*home) / ".local" / "share" / "pstack"
        : std::filesystem::path("/var/tmp");
    setenv("XDG_DATA_HOME", "", 1);
    check("empty XDG_DATA_HOME", {".", userDefault});
    unsetenv("XDG_DATA_HOME");
    check("unset XDG_DATA_HOME", {".", userDefault});
}
