# use gpu on colab

google colab上でGPUを利用する方法を解説します.

[google colab](https://colab.research.google.com/#create=true)にアクセスし, 適当なプロジェクトを作成します.

![Screenshot 2026-03-21 at 20-10-08 Untitled1.ipynb - Colab.png](Screenshot 2026-03-21 at 20-10-08 Untitled1.ipynb - Colab.png)

リボンメニューより`Change runtime type`を選択し, T4 GPUが使えるようにします.

![Screenshot_20260321_201643.png](Screenshot_20260321_201643.png)

![Screenshot_20260321_201830.png](Screenshot_20260321_201830.png)

google colab上は`ipython`のノートブック形式で`!<cmd>`のようなsyntaxでコマンドを実行できます.

- 例: nvidia-smiの結果(GPUのsummary)

![Screenshot_20260321_202207.png](Screenshot_20260321_202207.png)

他にもcudaコンパイラである`nvcc`などが利用できます.

ウィンドウ左からファイルアップロードするとカレントにファイルを設置できます.

![Screenshot_20260321_202524.png](Screenshot_20260321_202524.png)

入出力はこちらに開放されないのでechoをパイプしてください.

```sh
!echo "hoge" | ./<elf>
```

例として以下のreduction kernelを含むcudaをコンパイルし実行します. 通常配列のsumを数え上げるにはO(N)の計算量が必要ですが, GPUでのthread並列によりO(log N)の計算量で計算できます.

```c
#include <stdio.h>
#include <stdlib.h>

#define N (1 << 20)
#define BLOCK_SIZE 256

__global__ void reduce(const float *in, float *out, int n) {
    __shared__ float sdata[BLOCK_SIZE];

    int tid = threadIdx.x;
    int i = blockIdx.x * blockDim.x + threadIdx.x;

    sdata[tid] = (i < n) ? in[i] : 0.0f;
    __syncthreads();

    for (int s = blockDim.x / 2; s > 0; s >>= 1) {
        if (tid < s) sdata[tid] += sdata[tid + s];
        __syncthreads();
    }

    if (tid == 0) atomicAdd(out, sdata[0]);
}

int main() {
    size_t bytes = N * sizeof(float);

    float *h_in = (float *)malloc(bytes);
    srand(1337);
    for (int i = 0; i < N; i++) h_in[i] = (float)rand() / RAND_MAX;

    float *d_in, *d_out;
    cudaMalloc(&d_in, bytes);
    cudaMalloc(&d_out, sizeof(float));
    cudaMemcpy(d_in, h_in, bytes, cudaMemcpyHostToDevice);
    cudaMemset(d_out, 0, sizeof(float));

    int blocks = (N + BLOCK_SIZE - 1) / BLOCK_SIZE;
    reduce<<<blocks, BLOCK_SIZE>>>(d_in, d_out, N);

    float gpu_sum;
    cudaMemcpy(&gpu_sum, d_out, sizeof(float), cudaMemcpyDeviceToHost);

    printf("Sum: %.2f\n", gpu_sum);

    cudaFree(d_in);
    cudaFree(d_out);
    free(h_in);
    return 0;
}
```

```plain text
!ls
reduce.cu sample_data
!nvcc reduce.cu -arch=native
!./a.out
```

![Screenshot_20260321_211248.png](Screenshot_20260321_211248.png)

