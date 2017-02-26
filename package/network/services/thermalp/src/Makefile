THERMALP_LDFLAGS=$(LDFLAGS) -lcurl -lubox -ljson-c -luci -Wall -Werror -O2
DIRS=.
FILES=$(foreach dir, $(DIRS), $(wildcard $(dir)/*.c))
OBJS=$(patsubst %.c, %.o, $(FILES))

thermalp:$(OBJS)	
	$(CC) $(THERMALP_LDFLAGS) $(OBJS) -o $@

$(OBJS):%.o:%.c
	$(CC) -c $< -o $@

clean:
	rm  -f *.o thermalp