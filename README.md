# Kwatch

In real-world DevOps, security often takes a backseat to speed, leading to risky "quick fixes" like `docker run --privileged`. **kwatch** is the final safety net for these inevitable misconfigurations. Operating deeply at the kernel level via eBPF, it ignores container permissions and monitors actual syscall execution. If a container attempts to compromise the host—regardless of its privileges—kwatch detects the signature and terminates the process instantly, preventing a lazy configuration from becoming a root compromise.


## System Architecture

<img width="765" height="383" alt="kwatch_SYS_v2" src="https://github.com/user-attachments/assets/f6092e32-4d6b-49dd-9898-80c46fa9ae8c" />
