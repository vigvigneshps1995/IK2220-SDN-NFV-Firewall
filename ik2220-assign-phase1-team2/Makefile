SHELL := /bin/bash

app: 
	@cd application/sdn/ && make start

topo:
	@cd topology/ && sudo make topo

clean:
	@echo -n "Cleaning POX...      " 
	@cd application/sdn/ && make clean
	@echo -n "Cleaning Mininet...    "
	@cd topology/ && make clean
	@echo -n "System cleanup completed !	"
