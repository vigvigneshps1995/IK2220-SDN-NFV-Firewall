POX_PATH:=$(echo pwd)/ext/
POX_APP:=$(echo pwd)./pox.py log.level --DEBUG

MODULE:=POXController

start:
	@sudo $(POX_APP) $(MODULE)

clean:
	@sudo fuser -k 6633/tcp
