from forensic_model import forensic_ai_check

test_logs = [
    [1,1,1,167775999,0,0,0,0,0,0,0],   # likely normal
    [10,23,6,3232300990,1,1,1,1,1,1,1]  # max-range suspicious
]

def main():
    for log in test_logs:
        result = forensic_ai_check(log)
        print("Input:", log)
        print("Output:", result)
        print("------------")


if __name__ == "__main__":
    main()
