#include "json.h"
#include <unordered_map>
#include <map>
#include <vector>
#include <array>

int
main()
{
   std::unordered_map<std::string, std::map<std::string, std::vector<int>>> foo;
   foo["hello"]["world"].push_back(3);
   foo["goodbye"]["world"].push_back(99);

   std::cout << json(foo);

}


