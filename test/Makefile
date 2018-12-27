include proj.mk

CFLAGS=-fstack-protector-all -fPIE -pie -fno-exceptions -g -fvisibility=hidden -std=c99 -O3
WFLAGS=-Wall -Wextra -pedantic -Wcast-qual -Werror
LFLAGS=-pie -Wl,-z,relro,-z,now
OFLAGS=-pipe

# If we WANT to crosscompile
ifeq ($(CROSS),)

# Optionally suggest a default cross compiler here
# ifeq ($(CROSS_COMPILE),)
CROSS_COMPILE=arm-linux-gnueabihf-
# endif

# CROSS COMPILE ADDITIONS #
endif

CC=${CROSS_COMPILE}gcc
LD=${CROSS_COMPILE}gcc

OBJS = $(SRCS:%.c=%.o)

all: $(PROJ)
	@echo "Done"

em: clean
	@make CROSS=emulate

$(PROJ): $(OBJS)
	@echo "Linking: \033[0;32m$@\033[0m"
	@$(LD) $? $(LFLAGS) $(OFLAGS) -o $@
	
%.o: %.c
	@echo "Compiling \033[0;31m$<\033[0m"
	@$(CC) $(CFLAGS) $(DFLAGS) $(WFLAGS) $(OFLAGS) -c $< -o $@
	
clean: clean_objects
	@rm -f $(PROJ)
	@echo "Clean"

clean_objects:
	@rm -f *.o
	@echo "Cleaning objects..."
