from .cli import main

# The guard matters: steps start worker processes, and on macOS each worker
# re-imports this file. Without it every worker would run main() again.
if __name__ == "__main__":
    main()
