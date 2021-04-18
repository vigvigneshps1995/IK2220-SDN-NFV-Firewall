SHELL := /bin/bash

app: 
	@cd application/sdn/ && sudo make start

topo:
	@cd topology/ && sudo make topo

test:
	@sudo make clean && sudo make app && cd topology/ && sudo make test
	
clean:
	@echo -n "Cleaning POX...      " 
	@cd application/sdn/ && sudo make clean
	@echo -n "Cleaning Mininet...    "
	@cd topology/ && sudo make clean
	@echo -n "System cleanup completed !	\n"
