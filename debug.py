import traceback
import threading
import os.path
import sys

class DebugFile(object):
    __slots__ = 'target', 'label', 'buffer'
    def __init__(self, target, label=None):
        self.target = target
        self.label = label
        self.buffer = bytearray()
    def write(self, str):
        try:
            if type(str) is unicode:
                str = str.encode('utf8')
            self.buffer += str
            while True:
                index = self.buffer.find('\n')
                if index == -1: break
                self.annotate_line(self.buffer[0:index+1])
                del self.buffer[0:index+1]
        except BaseException:
            traceback.print_exc(file=real_stderr)
            raise
    def annotate_line(self, line):
        stack = list(reversed(traceback.extract_stack()))[3:6]
        self.target.write('[%s(%s)%s]\n' % (
            threading.current_thread().name,
            ','.join('%s:%s' % (os.path.basename(fi), ln)
                for (fi, ln, fu, te) in stack),
            '' if self.label is None else ':%s' % self.label))
        self.target.write('\t' + line)
    def __getattr__(self, name):
        return getattr(self.target, name)

real_stdout = sys.stdout
sys.stdout = DebugFile(sys.stdout, 'out')

real_stderr = sys.stderr
sys.stderr = DebugFile(sys.stderr, 'err')
