import os
import signal
def killMe():
    os.kill(os.getpid(), signal.SIGBUS)


killMe()
