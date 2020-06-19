#include "../include/Runner.h"
#include "../include/Validator.h"

int main(int argc, char** argv) {
    if ((argc != 4) || !input_validation::validate_args(argv)) {
        input_validation::show_usage(argv);
        exit(EXIT_FAILURE);
    }
    Runner mdump_runner { &argv[1] }; 
    mdump_runner.run();
    return 0;
}
