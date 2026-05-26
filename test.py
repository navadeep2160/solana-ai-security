from models.ollama_client import load_model


def main():

    llm = load_model("scanner_model")

    response = llm.invoke(
        "Explain Solana signer validation in 2 lines."
    )

    print("\n===== GEMINI RESPONSE =====\n")
    print(response.content)


if __name__ == "__main__":
    main()