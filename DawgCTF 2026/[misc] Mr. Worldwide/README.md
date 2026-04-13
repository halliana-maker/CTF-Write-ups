# Mr. Worldwide - DawgCTF 2026 Writeup

## 1. TL;DR
The challenge requires solving the **Traveling Salesperson Problem (TSP)** for a graph with 20 nodes. Because the server enforces a strict time limit, a standard Python brute-force approach is too slow. By implementing an optimized **Held-Karp algorithm (Bitmask Dynamic Programming)** and optimizing the iteration process, we calculated the minimum tour distance and retrieved the flag.

## 2. Provided Data and Interaction
We are given a netcat address: `nc nc.umbccd.net 23456`. No files were provided.

### Server Interaction:
1.  **Input from Server**: An integer $N$ (number of nodes), followed by an $N \times N$ adjacency matrix where `adj[i][j]` is the distance between node `i` and node `j`.
2.  **Output from Player**: The minimum distance required to visit every node exactly once and return to the starting node.

```text
$ nc nc.umbccd.net 23456
20
0 30 82 86 62 22 48 14 80 44 31 32 78 1 13 37 14 100 52 35
30 0 39 56 63 5 6 71 85 22 26 68 75 8 11 39 43 38 26 3
82 39 0 95 47 11 8 95 62 42 21 54 30 73 11 40 36 40 100 34
86 56 95 0 9 79 85 17 82 99 63 97 27 7 38 57 82 36 23 32
62 63 47 9 0 11 48 44 44 64 39 17 71 41 22 26 27 30 71 21
22 5 11 79 11 0 17 56 73 19 70 79 89 44 30 2 21 99 24 83
48 6 8 85 48 17 0 44 60 34 73 85 57 5 25 62 84 10 35 9
14 71 95 17 44 56 44 0 7 70 84 84 50 38 4 82 44 2 100 57
80 85 62 82 44 73 60 7 0 26 59 94 11 82 20 99 42 59 85 40
44 22 42 99 64 19 34 70 26 0 96 7 42 8 83 50 26 15 98 3
31 26 21 63 39 70 73 84 59 96 0 27 60 5 94 91 62 28 54 36
32 68 54 97 17 79 85 84 94 7 27 0 33 59 22 14 77 98 96 68
78 75 30 27 71 89 57 50 11 42 60 33 0 66 90 97 54 99 65 3
1 8 73 7 41 44 5 38 82 8 5 59 66 0 61 23 96 5 83 86
13 11 11 38 22 30 25 4 20 83 94 22 90 61 0 65 87 25 2 40
37 39 40 57 26 2 62 82 99 50 91 14 97 23 65 0 31 24 96 73
14 43 36 82 27 21 84 44 42 26 62 77 54 96 87 31 0 97 92 72
100 38 40 36 30 99 10 2 59 15 28 98 99 5 25 24 97 0 19 20
52 26 100 23 71 24 35 100 85 98 54 96 65 83 2 96 92 19 0 57
35 3 34 32 21 83 9 57 40 3 36 68 3 86 40 73 72 20 57 0

Enter minimum tour distance:
```
Between 3s and 5s, the server output:
> Time limit exceeded!   
> Invalid input!

So we need a program to solve the challenge as fast as possible.

## 3. Problem Analysis
The problem asks for the minimum distance to visit all cities and return to the start. This is the classic **Traveling Salesperson Problem (TSP)**.

### Complexity:
*   **Nodes ($N$):** 20.
*   **Brute Force ($O(N!)$):** $20! \approx 2.4 \times 10^{18}$, which is impossible to compute.
*   **Dynamic Programming ($O(2^N \cdot N^2)$):** The Held-Karp algorithm reduces the complexity significantly. For $N=20$, $2^{20} \approx 1,000,000$. The total operations are roughly $10^6 \times 20^2 \approx 400,000,000$.

While 400 million operations are manageable in C++ or PyPy, standard **CPython** (the default Python interpreter) struggles to complete this within a 5-second timeout due to loop overhead.

## 4. Initial Guesses / First Try
Our first attempt involved a basic Bitmask DP using a dictionary to store states. 

**Result:** `Time limit exceeded!`
The server closed the connection before the script could finish. Even though the logic was correct, the constant dictionary lookups and nested loops in standard Python were too slow for the $N=20$ threshold.

## 5. Exploitation Walkthrough / Flag Recovery
To beat the timer using only Python, we had to optimize the Held-Karp implementation:
1.  **Iterative Subset Generation**: Instead of checking every integer from $1$ to $2^{20}$, we used `itertools.combinations` to only generate masks with a specific number of set bits.
2.  **State Management**: We used a dictionary that we cleared at each step (moving from subset size $r$ to $r+1$) to minimize memory overhead.
3.  **Fixed Starting Point**: Since the tour is a cycle, we fixed the starting node at index `0`.

### The Solver Script
```python
from pwn import *
import itertools

def solve_tsp(n, adj):
    nodes = range(n)
    all_nodes_set = set(range(1, n))
    
    # dp[mask] = {last_node: distance}
    # We only need the previous subset size to calculate the current one
    dp = {1: {0: 0}}

    for r in range(2, n + 1):
        new_dp = {}
        # Get all combinations of size r that include node 0
        for subset in itertools.combinations(all_nodes_set, r - 1):
            mask = 1
            for node in subset:
                mask |= (1 << node)
            
            res_for_mask = {}
            for next_node in subset:
                prev_mask = mask ^ (1 << next_node)
                if prev_mask in dp:
                    # Find min distance to next_node from any previous node in mask
                    best_dist = float('inf')
                    for prev_node, total_dist in dp[prev_mask].items():
                        d = total_dist + adj[prev_node][next_node]
                        if d < best_dist:
                            best_dist = d
                    
                    if best_dist != float('inf'):
                        res_for_mask[next_node] = best_dist
            
            if res_for_mask:
                new_dp[mask] = res_for_mask
        
        # Clear old DP to save memory/speed
        dp = new_dp

    ans = float('inf')
    for mask, nodes_in_mask in dp.items():
        for last_node, dist in nodes_in_mask.items():
            ans = min(ans, dist + adj[last_node][0])
    
    return ans

def main():
    context.log_level = 'info'
    
    io = remote('nc.umbccd.net', 23456)
    
    try:
        line = io.recvline().decode().strip()
        while not line or not line[0].isdigit():
            line = io.recvline().decode().strip()
        n = int(line)
        log.info(f"Solving for N={n}")
        
        adj = []
        for _ in range(n):
            adj.append(list(map(int, io.recvline().split())))
            
        log.info("Calculating TSP")
        result = solve_tsp(n, adj)
        log.info(f"Result found: {result}")
        
        io.sendlineafter(b":", str(result).encode())
        print(io.recvall().decode())
        
    except EOFError:
        log.error("Server closed connection.")
    finally:
        io.close()

if __name__ == "__main__":
    main()
```

### Execution:
The script successfully computed the result for $N=20$ in roughly 4 seconds. 
The server accepted the value and returned the flag.

**Flag:** `DawgCTF{wh4t_l4ngu4ag3_d1d_y0u_us3?}`

## 6. What We Learned
1.  **Computational Thresholds**: For $N=20$, $O(N!)$ is impossible, but $O(2^N \cdot N^2)$ is the intended solution.
2.  **Python Optimization**: CPython is slow for large loops. To pass strict time limits in CTFs, it is crucial to use built-in functions like `itertools` or run the script using the **PyPy3** interpreter.
3.  **TSP Variants**: Identifying a problem as TSP early allows you to use established algorithms rather than attempting to reinvent a pathfinding solution.