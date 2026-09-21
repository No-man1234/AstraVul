import pytest
from src.parser.slicer import ASTSlicer, CodeSlice


@pytest.fixture
def slicer():
    return ASTSlicer()


def test_buffer_overflow_slicing(slicer):
    code = """
    #include <stdio.h>
    #include <string.h>

    void handle_request(char *input) {
        char buf[32];
        if (strlen(input) > 0) {
            strcpy(buf, input);
        }
    }
    """
    slices = slicer.slice_code(code)
    assert len(slices) == 1
    s = slices[0]
    assert s.sink_function == "strcpy"
    assert s.taint_variable == "buf"
    assert s.cwe_candidate == "CWE-120"
    assert s.slice_tokens <= 150
    assert "strcpy(buf, input);" in s.slice_code


def test_use_after_free_slicing(slicer):
    code = """
    #include <stdlib.h>

    void cleanup() {
        int *data = (int *)malloc(sizeof(int));
        free(data);
        *data = 42;
    }
    """
    slices = slicer.slice_code(code)
    assert len(slices) == 1
    s = slices[0]
    assert s.sink_function == "free"
    assert s.taint_variable == "data"
    assert s.cwe_candidate == "CWE-416"
    assert s.slice_tokens <= 150
    assert "free(data);" in s.slice_code


def test_command_injection_slicing(slicer):
    code = """
    #include <stdlib.h>
    #include <stdio.h>

    void execute(char *target) {
        char cmd[128];
        sprintf(cmd, "nslookup %s", target);
        system(cmd);
    }
    """
    slices = slicer.slice_code(code)
    # Might detect sprintf and system
    sinks = [s.sink_function for s in slices]
    assert "system" in sinks
