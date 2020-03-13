import subprocess
import glob
import os.path

class CoreMonitor( object ):
   def __init__( self, args, childproc = None):
      with open( "/proc/sys/kernel/core_pattern" ) as f:
         self.core_pattern = f.read().strip()
      if args is None:
          self.exe = "python"
          self.pid = os.fork()
          if self.pid == 0:
              os._exit(childproc())
          else:
              os.waitpid(self.pid, 0)

      else:
          p = subprocess.Popen( args, stdout=subprocess.PIPE )
          self.pid = p.pid
          self.exe = os.path.basename( args[0] )
          ( self.input, self.output ) = p.communicate()
      self.corefile = self.core_pattern.replace( "%e", self.exe )
      self.corefile = self.corefile.replace( "%p", "%d" % self.pid )
      self.corefile = self.corefile.replace( "%t", "*" )

   def core( self ):
      files = glob.glob( self.corefile )
      if files:
         return files[0]
      return None


if __name__ == "__main__":
   cm = CoreMonitor([ "tests/segv", "hello" ] )
   print cm.core()
