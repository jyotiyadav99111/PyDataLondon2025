# tools/general_query.py
import os
from langchain.chat_models import ChatOpenAI
from langchain.schema import SystemMessage, HumanMessage

# Use the same LLM instance (hard-code key here for now or import from a central config)
_llm = ChatOpenAI(
    model_name="gpt-3.5-turbo",
    temperature=0,
    openai_api_key=os.getenv("OPENAI_API_KEY"))

def general_query(
    question: str
) -> str:
    """
    Handle arbitrary questions that don’t mention a domain or IP.
    Simply passes the question to the LLM and returns its answer.
    """
    messages = [
        SystemMessage(content="You are a helpful cybersecurity assistant. you can look into the memory to check for the answers aksed by the user"),
        HumanMessage(content=question)
    ]
    resp = _llm(messages)
    return resp.content.strip()