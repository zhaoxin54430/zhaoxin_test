CLATDM_LDFLAGS=$(LDFLAGS) -lshmem -lcurl -ljson-c
DIRS=.
FILES=$(foreach dir, $(DIRS), $(wildcard $(dir)/*.c))
OBJS=$(patsubst %.c, %.o, $(FILES))

clatdm:$(OBJS)	
	$(CC) $(CLATDM_LDFLAGS) $(OBJS) -o $@

$(OBJS):%.o:%.c
	$(CC) -c $< -o $@

clean:
	rm  -f *.o clatdm