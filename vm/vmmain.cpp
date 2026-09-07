#include <windows.h>
#include "vmmain.hpp"

// just realized that " forever threads " will need to have their own memory. 
// we can separate one-time runs from the forever threads. this way there is no deadlock

