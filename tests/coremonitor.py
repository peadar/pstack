import subprocess
import sys
import glob
import os.path
import os

class CoreMonitor( object ):
   def __init__( self, args, childproc = None):
      with open( "/proc/sys/kernel/core_pattern" ) as f:
         self.core_pattern = f.read().strip()
      if args is None:
          self.pid = os.fork()
          self.exe = "*"
          self.output = None
          if self.pid == 0:
              os._exit(childproc())
          else:
              os.waitpid(self.pid, 0)
      else:
          p = subprocess.Popen( args, stdout=subprocess.PIPE )
          self.pid = p.pid
          self.exe = os.path.basename( args[0] )
          ( self.output, self.errors ) = p.communicate()
      self.corefile = self.core_pattern.replace( "%e", self.exe )
      if '%p' in self.core_pattern:
          self.corefile = self.corefile.replace( "%p", "%d" % self.pid )
      elif open("/proc/sys/kernel/core_uses_pid").read() == "1\n":
          self.corefile = "%s.%d" % (self.corefile, self.pid)
      self.corefile = self.corefile.replace( "%t", "*" )
      print("expected core %s" % self.corefile)

   def __enter__( self ):
      return self

   def __exit__( self, *args ):
      c = self.core()
      if c:
         if "PSTACK_TEST_KEEPCORE" not in os.environ:
            print("unlinking core %s" % self.corefile)
            os.unlink(c)
         else:
            print("keeping core %s" % self.corefile)

   def core( self ):
      files = glob.glob( self.corefile )
      if files:
         return files[0]
      print("expected core '%s' did not appear" % self.corefile )
      return None

if __name__ == "__main__":
   cm = CoreMonitor([ "tests/segv", "hello" ] )
