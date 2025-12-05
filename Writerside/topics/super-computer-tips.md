# super computer tips

## job scheduler commands

### `slirm`
- submit job
  - `sbatch <job script>`
- check job state
  - `sinfo -N`, `squeue`
- kill job
  - `scancel <job number>`

### open PBS
- submit job
  - `qsub <job script>`
- check job state
  - `qstat -q`
- kill job
  - `qdel <job number>`