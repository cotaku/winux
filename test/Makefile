EXE =test.exe
OBJS = test.obj
RES = test.res

LINK_FLAG = /subsystem:console
ML_FLAG = /c /coff

$(EXE): $(OBJS) $(RES)
	Link $(LINK_FLAG) $(OBJS) $(RES)

.asm.obj:
	ml $(ML_FLAG) $<
.rc.res:
	rc $<

clean:
	del *.obj
	del *.res
