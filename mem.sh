export TWO_TASK=orcl
export DOCUMENT_ROOT=/home/xjb
export DB=ORCL
export DB_USER=tms
export DB_PWD=tms
export ICS_SIGN=2
rm *.log
valgrind --tool=memcheck --leak-check=full --show-reachable=yes --vex-iropt-register-updates=allregs-at-mem-access --vex-iropt-register-updates=allregs-at-each-insn --log-file=mem.log tms&
