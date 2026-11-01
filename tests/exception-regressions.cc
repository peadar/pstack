#include "libpstack/exception.h"

#include <iostream>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <utility>

using pstack::Exception;

static_assert(!std::is_nothrow_copy_constructible_v<Exception>);
static_assert(!std::is_nothrow_copy_assignable_v<Exception>);
static_assert(std::is_nothrow_move_constructible_v<Exception> ==
              std::is_nothrow_move_constructible_v<std::ostringstream>);
static_assert(std::is_nothrow_move_assignable_v<Exception> ==
              std::is_nothrow_move_assignable_v<std::ostringstream>);

namespace {
void checkMessage(const Exception &exception, std::string_view expected) {
    if (exception.what() != expected)
        throw std::runtime_error("exception message mismatch: " + std::string(exception.what()));
}

void testExceptions() {
    Exception original;
    checkMessage(original, "");
    original << "source " << 42;
    checkMessage(original, "source 42");

    Exception copied(original);
    copied << " copied";
    checkMessage(copied, "source 42 copied");
    checkMessage(original, "source 42");

    Exception assigned;
    assigned << "old destination text";
    checkMessage(assigned, "old destination text");
    assigned.getStream().setstate(std::ios::failbit);
    assigned = original;
    checkMessage(assigned, "source 42");
    assigned << " assigned";
    checkMessage(assigned, "source 42 assigned");
    assigned = original;
    checkMessage(assigned, "source 42");
    const Exception &self = assigned;
    assigned = self;
    assigned << " self";
    checkMessage(assigned, "source 42 self");

    Exception moved(std::move(copied));
    checkMessage(moved, "source 42 copied");
    moved << " moved";
    checkMessage(moved, "source 42 copied moved");
    assigned = std::move(moved);
    checkMessage(assigned, "source 42 copied moved");
    assigned << " assigned";
    checkMessage(assigned, "source 42 copied moved assigned");

    try {
        throw Exception() << "thrown " << 7;
    } catch (const Exception &exception) {
        checkMessage(exception, "thrown 7");
        exception << " caught";
        checkMessage(exception, "thrown 7 caught");
    }
}
}

int main() {
    try {
        testExceptions();
    } catch (const std::exception &exception) {
        std::cerr << "Exception regression: " << exception.what() << '\n';
        return 1;
    }
}
