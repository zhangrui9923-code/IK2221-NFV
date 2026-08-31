#!/usr/bin/python3

import os
import subprocess
import time
import signal
import logging

# [1/4] Replace print with log.info
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger("click_wrapper")

"""
This is an helper wrapper to run Click on top of POX
This will be used in the NFV part of the project
"""

click_pids = []

def start_click(configuration, parameters, stdout="/tmp/click.out", stderr="/tmp/click.err"):

  # TODO: What do you want to do with the outputs?
  # Maybe you want them to a file? tee and > can be your friends!
  redirect = ""

  # Remove the '&' symbol at the end of the command, otherwise the p.pid will be the PID of the bash instead of the click process.
  cmd = f"sudo click {configuration} {parameters} {redirect} >{stdout} 2>{stderr}"
  log.info(f"Launching click with command {cmd}")
  
  # Launch the Click process
  p = subprocess.Popen(cmd, shell=True)
  
  # Check if the Click process is actually started successfully, to prevent the Click script from crashing instantly due to syntax errors.
  time.sleep(0.5)
  if p.poll() is not None:
      log.error(f"Failed to start Click! Return code: {p.returncode}. Check {stderr} for syntax errors.")
      return None

  log.info(f"Click launched with PID {p.pid}")
  
  global click_pids
  click_pids.append(p.pid)
  return p


def handle_kill(sig, frame):
  # Iterate through click_pids to send SIGTERM signal precisely.
  global click_pids
  log.info("Got kill signal. Notify all click processes...")
  
  for pid in click_pids:
      try:
          # Use sudo kill to send SIGTERM signal to the specific PID
          subprocess.run(f"sudo kill -SIGTERM {pid} || true", shell=True, check=False)
      except Exception as e:
          log.warning(f"Error killing PID {pid}: {e}")
          
  click_pids.clear()
  exit(0)

def killall_click():
  subprocess.check_output("sudo killall -SIGTERM click || true", shell=True)


# Forward SIGINT/SIGTERM to all tracked Click processes before exiting
signal.signal(signal.SIGINT, handle_kill)
signal.signal(signal.SIGTERM, handle_kill)