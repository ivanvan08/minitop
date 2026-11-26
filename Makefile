CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -std=gnu11 -Iinclude
SANFLAGS = -fsanitize=address,undefined
# libcurl is a link-time and header-time requirement only: src/curlshim.c
# dlopen()s it when a mode 2/3 engine starts. --as-needed keeps the DT_NEEDED
# entry out because no object references a libcurl symbol, so mode 1 never
# maps the library. -ldl is the historical home of dlopen().
LDLIBS  = -Wl,--as-needed -lcurl -ldl

BIN     = minitop

# The engines compile against <curl/curl.h> even though the library is loaded
# with dlopen() at run time. Fail with an instruction instead of a bare
# "curl/curl.h: No such file or directory" from the first compile recipe.
# clean stays usable on a machine without the development package.
ifneq ($(MAKECMDGOALS),clean)
CURL_HEADERS := $(shell $(CC) $(CFLAGS) -E -x c -include curl/curl.h /dev/null >/dev/null 2>&1 && echo ok)
ifeq ($(CURL_HEADERS),)
$(error libcurl development headers not found (need curl/curl.h); install libcurl)
endif
endif

BACKEND_SRCS = src/curlshim.c src/sysinfo.c src/cpu.c src/flags.c src/procs.c src/display.c src/tui.c src/input.c src/gpu.c src/config.c src/trust.c src/model.c src/llm.c
BACKEND_OBJS = $(BACKEND_SRCS:.c=.o)

MAIN_SRC = src/main.c
MAIN_OBJ = $(MAIN_SRC:.c=.o)

TEST_SRC = tests/test_backend.c
TEST_BIN = tests/tests
GPU_TEST = tests/test_gpu
CFG_TEST = tests/test_config
MODEL_TEST = tests/test_model
LLM_TEST = tests/test_llm

.PHONY: all release test test-asan clean

all: $(BIN)

# release: the binary people ship. -Os because size is a stated goal here: the
# release must stay under procps-ng top's 143 KB, and -Os takes it to ~109 KB
# against ~146 KB at -O2. The unwind tables, the .comment ident string and the
# build id are dropped for the same reason; none of them is used at run time.
release: clean
	$(CC) -Wall -Wextra -Os -std=gnu11 -Iinclude -flto -ffunction-sections -fdata-sections \
	      -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident \
	      $(MAIN_SRC) $(BACKEND_SRCS) \
	      -Wl,--gc-sections -Wl,--build-id=none -Wl,-O1 -s -o $(BIN) $(LDLIBS)
	@ls -l $(BIN)

$(BIN): $(MAIN_OBJ) $(BACKEND_OBJS)
	$(CC) $(CFLAGS) $(MAIN_OBJ) $(BACKEND_OBJS) -o $@ $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_BIN): $(TEST_SRC) $(BACKEND_OBJS)
	$(CC) $(CFLAGS) $(TEST_SRC) $(BACKEND_OBJS) -o $@ $(LDLIBS)

$(GPU_TEST): tests/test_gpu.c src/gpu.c include/gpu.h
	$(CC) $(CFLAGS) tests/test_gpu.c src/gpu.c -o $@

$(CFG_TEST): tests/test_config.c src/config.c include/config.h
	$(CC) $(CFLAGS) tests/test_config.c src/config.c -o $@

$(MODEL_TEST): tests/test_model.c $(BACKEND_OBJS)
	$(CC) $(CFLAGS) tests/test_model.c $(BACKEND_OBJS) -o $@ $(LDLIBS)

$(LLM_TEST): tests/test_llm.c $(BACKEND_OBJS)
	$(CC) $(CFLAGS) tests/test_llm.c $(BACKEND_OBJS) -o $@ $(LDLIBS)

test: $(TEST_BIN) $(GPU_TEST) $(CFG_TEST) $(MODEL_TEST) $(LLM_TEST)
	./$(TEST_BIN)
	./$(GPU_TEST)
	./$(CFG_TEST)
	./$(MODEL_TEST)
	./$(LLM_TEST)

test-asan: $(TEST_SRC) $(BACKEND_SRCS)
	$(CC) $(CFLAGS) $(SANFLAGS) $(TEST_SRC) $(BACKEND_SRCS) -o $(TEST_BIN) $(LDLIBS)
	./$(TEST_BIN)
	$(CC) $(CFLAGS) $(SANFLAGS) tests/test_gpu.c src/gpu.c -o $(GPU_TEST)
	./$(GPU_TEST)
	$(CC) $(CFLAGS) $(SANFLAGS) tests/test_config.c src/config.c -o $(CFG_TEST)
	./$(CFG_TEST)
	$(CC) $(CFLAGS) $(SANFLAGS) tests/test_model.c $(BACKEND_SRCS) -o $(MODEL_TEST) $(LDLIBS)
	./$(MODEL_TEST)
	$(CC) $(CFLAGS) $(SANFLAGS) tests/test_llm.c $(BACKEND_SRCS) -o $(LLM_TEST) $(LDLIBS)
	./$(LLM_TEST)

clean:
	rm -f $(MAIN_OBJ) $(BACKEND_OBJS) $(TEST_BIN) $(GPU_TEST) $(CFG_TEST) $(MODEL_TEST) $(LLM_TEST) $(BIN)
