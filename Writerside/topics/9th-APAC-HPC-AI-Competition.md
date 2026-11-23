# 9th APAC HPC-AI 挑战赛

> APAC HPC-AI 挑战赛是由国际高性能计算与人工智能咨询委员会（HPC-AI Advisory Council）主办、亚太地区多国权威超算中心联合支持的国际性大学生超算与人工智能竞赛。
> 共有50支队伍报名参赛，其中32支队伍晋级展示环节。

最终，我们取得了以下成绩：
- AI: Firmus超级计算机Basic, 8.8k goodput TPS
- HPC: Gadi超级计算机Basic, 416 ranks，平均步时1.98 s

I'm tsune, the captain of the Kisarazu Big Branch w/ Riken.
Kisarazu Big Branch w/ Riken is the HPC team of the National Institute of Technology, Kisarazu College, Japan.
Riken-RCCS supported us with HPC resources from 玄界, which has Intel Xeon Platinum 8490H CPUs and NVIDIA H100 GPUs.

Thb, 玄界 was very uncomfortable.
PJM, which is the job scheduler developed by Fujitsu, didn't allocate/separate the resources of the node correctly, which made Intel VTune unavailable without stack tracing.
Perf mode works; driver mode doesn't work. FS was slow.
When the application conducts heavy FS, the node will crash (WTF?).
Absolute shit HPC.

I am currently a trainee at Riken-RCCS and went to an internship at Riken-RCCS last year.
In the internship, I optimized a trigonometric function kernel for A64Fx (富岳超级计算机在Riken-RCCS的CPU) and achieved a 16x faster trigonometric function implementation with handmade assembly.
Therefore, I gained knowledge of pipeline optimization that is very useful for compute-bound application tuning.
However, the HPC task, OpenFOAM-v2512, was a nightmare because of its memory access and shit matrix structure.

Also, I'm a top CTF player. ("Top" is not self-praise; I've won many CTF competitions worldwide.)
I've been deeply involved in computer science and competitive programming, which I needed to keep my brain sharp.
CTF is dead, everyone says. And I think so too. Admittedly, I can author AI-impossible challenges.
However, humans also cannot solve that.
The fact that an AI-impossible challenge exists shows the author has smart intelligence, not that CTF is still alive.
Therefore, I do understand what cs competition is going on. And as I expected, this year's HPC-AI Competition became the AI-slop competition.

I felt very bored in the middle of the competition period.
The cluster queue was occupied with AI agents' jobs, agentic kernel optimization produced significant improvements, and the agent worked fully throughout the competition period.
Doing AI slop was the smart option to win the competition.
But I didn't get any sense of motivation from that.
There is no academic interest.
If so, consuming my tokens for bug bounty is much more valuable and profitable lol.

CTFs are dead.

Competitive programming is dead.

HPC competitions are dead.

Furthermore, I felt other team members weren't interested in optimization.
There was no technical discussion about optimization, which also made me bored more.
Eventually, I did most of the experiments even I made many tools to share experiments and their purpose.
(That's fine tbh; no one should consume such a freaking competition)

## Maximize Your Brain, Not Your Agent

Here's a graph for the total number of jobs each teams sent in the competition period.

![](team_cumulative.png)

We can observe the obvious AI-sloppers. :joy:

Dear sloppers, maximize your brain, not your agent.
Have you ever thought about what humans win over LLMs?
That is obviously the context memory system.
1M context is not enough for long-term competition.
Our brain is not a bottleneck if we are smart.

If you are long in the computer science competition, you must know that our brains have been rotten by LLMs.
Never gonna give you up. There is still a competition that requires smart brains.

<inline-frame src="https://player.bilibili.com/player.html?isOutside=true&amp;aid=117508073855489&amp;bvid=BV15Yno6zEfr&amp;cid=43078976876&amp;p=1" width="100%" height="450px"></inline-frame>

Determining what to prioritize and assuming what will be a game changer are important, and we should keep them in mind in the HPC competition.
If you keep participating in the HPC competition, use your brain and trust your intelligence.

## OpenFOAM OCC DrivAer

![Screenshot_20261111_150225.png](Screenshot_20261111_150225.png)

[Open-closed cooling DrivAer variant with Static Mesh](https://develop.openfoam.com/committees/hpc/-/tree/develop/incompressible/simpleFoam/occDrivAerStaticMesh)

I do dislike the HPC task.
And I believe no one likes the HPC task in the AI era.
In the most of stereotype HPC applications have negative legacy.
OpenFOAM is a good example.
OpenFOAM tried to make it easy for everyone to write solvers using an LDU matrix and a C++ template nightmare.
However, the root cause of worse cache performance and bad memory access is at this point.
Even if we optimize the mesh, the fucking unresolvable wall will block our optimization.
However, I'd like to ask you: is agentic optimization, such as kernel audit and kernel optimization is valurable in the context of HPC competitions?
I argue not.
If kernel optimization is allowed, we should use an alternative simulation application that is NOT for stupid people.
Optimization on negative legacy is just a waste of time.

HPC task is so silly.
Therefore, OpenFOAM optimization didn't motivate us.

> from above, machine translated

OpenFOAM-v2512 is a CFD (computational fluid dynamics) application.
OpenFOAM can express equations abstractly through complex C++ templates and macros, so many people can write their own solvers. That is why it became so widespread.
In a simulation, the domain is decomposed into subdomains. Each subdomain is computed in parallel and exchanges data with its neighbors (halo communication).

In this competition, the tasks were benchmarks on 1, 2, and 4 nodes with simulation times of 40, 80, and 150, respectively. The evaluation metric was the optimization of the 4-node benchmark.
Teams on ASPIRE 2A could use up to 512 ranks, and teams on Gadi up to 416 ranks.
Patching the algorithms of the compute kernels themselves was prohibited.

In exchange for its abstraction power, OpenFOAM-v2512 adopts the LDU matrix format and is known for its poor cache hit rate.
Profiling with Intel VTune showed that more than 30% of memory accesses were DRAM-bound and that the core pipeline was barely utilized.
On top of DRAM access, MPI, which handles inter-process and inter-node communication, accounted for nearly 40% of the runtime.
The bottleneck was obviously data access.

### Profile method using dry-run

We had limited HPC credits, so we built our own profiler around a lightweight dry-run option to compare the existing domain decomposition algorithms.
This profiler visualized cases where the workload was concentrated on specific processes, and its results correlated highly with actual MPI profiling.
We profiled and compared the decomposition algorithms implemented in OpenFOAM-v2512. Scotch, a graph-based decomposition, partitioned the domain best, so we adopted Scotch.

### Custom inter-Node faces optimizer

MPI communication latency differs between inter-node, inter-NUMA, and intra-NUMA (core-to-core) communication.
Inter-node communication goes over the network through UCC/UCX, so its latency is obviously higher than inter-NUMA or core-to-core communication within the same NUMA node.
We profiled the Scotch decomposition per node and found large differences in communication volume between node pairs.
Therefore, we built an optimizer that non-destructively moves processes to other nodes.
The optimizer uses simulated annealing and mixed-integer programming to search for a rank binding that minimizes the maximum inter-node communication volume.
The MPI share of the total runtime dropped by about 5%, and we confirmed the method's effectiveness through benchmarks and dynamic profiling.

We tried to resolve the data access bottleneck only through domain decomposition.
I suppose not stepping into compute kernel patches is why our HPC track result stayed where it was.
However, improving cache behavior fundamentally requires changing the matrix format, so I doubt kernel patches matter that much.
Also, plain MPI flag tuning didn't interest us at all, so I'd call it a defeat caused by intelligence.

![](15.png)

![](30.png)

## Qwen 3

Qwen is a family of large language models from Alibaba.
The model specified for this task, Qwen3-235B-A22B, is an open-weight model and the first Qwen series to adopt QK-Norm and to drop shared experts.
It is an MoE architecture with GQA, 94 layers, and 128 experts. The model is about 236 GB, so it doesn't fit on typical consumer GPUs. It is literally a *large* language model.

In the benchmark, one request consists of 4000 input tokens and 200 output tokens, measured by AIPerf.

### PD disaggregation

Transformer LLM inference is split into two phases, Prefill and Decode. Only the KV cache is transferred between them.
This task required PD disaggregation, an inference architecture that serves Prefill and Decode on physically separate GPUs.

PD disaggregation was originally designed to assign different compute resources to Prefill and Decode.
In Transformer LLMs, Prefill is compute-bound and Decode is memory-bound.
For example, the H100 and H200 have the same number of SMs, so you could use H100s for Prefill and H200s, with more memory headroom, for Decode.
In this competition, however, both Prefill and Decode ran on H200s.

We first calculated the serving cost from the Qwen3 specification.
As mentioned above, the weights alone are 236 GB, so Tensor Parallelism across two or more H200s was required.
We chose an architecture that runs TP=2 for both Prefill and Decode and scales it out with Data Parallelism.
The KV cache size can be calculated deterministically from Qwen's dimensions and layer count. From these, we calculated values such as the maximum number of tokens the decode side can hold.

The benefit of PD disaggregation is that Prefill and Decode can be optimized independently.
For example, a Prefill-heavy PD ratio gives a pure TTFT improvement. Likewise, ITL can be optimized independently on the Decode side.

### Decode

We optimized Decode first, for a simple reason: Decode performance determines the maximum concurrency.
This track had strict TTFT and ITL limits. Average TTFT had to be under 3000 ms and average ITL 20 ms or less. Only requests meeting these limits counted as goodput.
The performance metric was goodput-only tokens/s, and goodput requests also had to make up at least 90% of all requests.
These strict requirements make the benchmark closer to real-world serving.
For example, increasing concurrency improves overall TPS, but ITL grows with it.
Similarly, a huge prefill batch size increases parallelism per batch and improves performance by reducing overhead, but TTFT gets worse.
TTFT and ITL therefore matter for guaranteeing acceptable performance for each request.

Decode has a technique called Speculative Decoding, where a small dense model serves as a draft model and predicts tokens.
The main model verifies the tokens predicted by the draft model, so accuracy is not degraded.
We adopted Speculative Decoding as our first optimization step, because whether you use it changes the number of FFN passes per step. That decision had to come before any profiling to identify the bottleneck.
In the first half of the competition we used a 0.6B draft model trained with LMSYS's SpecForge. In the second half we used a 0.6B draft model published by Nebius, trained with LK-loss.

Next, we profiled the decode GPUs with NVIDIA Nsight Systems.
We mapped the enormous number of CUDA Graphs in a batch down to architecture-level components such as GQA, RMSNorm, and Embedding.
Verifying the speculative tokens consumed 2700 CUDA Graphs (about 99.25% of the batch), and the MoE kernel within it was the bottleneck.
Keeping Amdahl's law in mind is the most important thing when optimizing.
There is a parameter to change the draft model's attention backend. But would swapping a kernel that takes less than 1% of the batch be a game changer? Of course not.
We always aimed for profiling-driven optimization and kept the problem-solving loop effective and efficient.
To improve the MoE computation, we adopted DP-attention and benchmarked MoE backends including MegaMoE, DeepGEMM, HPC-Ops, and Triton.
We chose MegaMoE and ran DP-attention across two DP ranks. This halved the MoE computation per GPU and processed tokens with faster CUDA kernels.
In the end, 4 decode GPUs served 216 concurrent requests while ITL still had headroom.

![](47.png)

![](48.png)

### Prefill

For Prefill, we profiled first as well.
The MoE kernel took about 45% of the batch, and NCCL AllReduce took 11%, so communication was also somewhat of a bottleneck.
Looking at the FFN layers, the MoE kernel's CUDA Graph latency differed by about 2 ms between GPUs. NCCL AllReduce was waiting on this synchronization, which inflated its share.
The NCCL AllReduce itself took only about 0.2 ms, so the dominant factor was the MoE kernel time gap caused by Expert Parallelism imbalance.

Based on this, we used EPLB with a static placement to replicate frequently routed experts on both GPUs of the TP group, and confirmed a Prefill performance improvement.

We also applied DP-attention to Prefill and increased the batch size as far as TTFT allowed, so Prefill could process more requests in parallel.

We further fused multiple CUDA Graphs to reduce CUDA Graph launch overhead and tuned MegaMoE. Without a single kernel patch, we reached 7.8k goodput TPS.

![](53.png)

![](55.png)

### Final topology

Our final setup used 12 GPUs for Prefill and 4 GPUs for Decode.
Prefill ran three TP=2, DP=2 DP-attention workloads, and Decode ran one TP=2, DP=2 DP-attention workload.
Both Prefill and Decode were highly optimized, and TTFT and ITL both met the competition's strict limits.

With this performance, we took first place in the AI track.

```plain text
check_result logs/31211/g1/aiperf-31211.log 
Time to First Token (ms) avg: 1769.80, VALID
Time to First Token (ms) p90: 2024.08, VALID
Time to First Token (ms) p50: 1723.59, VALID
Inter Token Latency (ms) avg: 14.71, VALID
Goodput (requests/sec): 44.35, VALID
Good-request fraction (approx): 97.82%, VALID
Overall: VALID
Good output token/s: 8870.00
```

[](https://gist.github.com/Yayoi-cs/6de3ba56dfc086bd85172b74eadc3039)


