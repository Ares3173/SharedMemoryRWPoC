add_executable(Core WIN32
pch.h
source.cpp)

target_link_libraries(Core PRIVATE spdlog::spdlog)

target_compile_features(Core PRIVATE cxx_std_23)