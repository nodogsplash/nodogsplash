

.PHONY: all tests
all: tests

tests: run_test_conf run_tests_state_file

# conf tests
run_test_conf:
	$(MAKE) -C ./conf/ tests

# state_file tests
run_tests_state_file:
	$(MAKE) -C ./state_file/ tests

clean:
	$(MAKE) -C ./conf/ clean
	$(MAKE) -C ./state_file/ clean
