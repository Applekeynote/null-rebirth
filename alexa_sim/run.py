"""Local development entry point. Installed environments can run server directly."""
from pathlib import Path
import runpy,site,sys
root=Path(__file__).resolve().parents[1]
if (root/'.mcpdeps').is_dir():site.addsitedir(str(root/'.mcpdeps'))
sys.path[:0]=[str(root),str(root/'source')]
runpy.run_module('alexa_sim.server',run_name='__main__')
