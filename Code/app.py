"""
streamlit_app.py

Streamlit-based chat app for the Agentic Maliciousness Query Agent.
Separates history and input into fixed containers for a true chat UX.
""" 
import os
import re
from langchain_openai import ChatOpenAI  
from langchain.agents import AgentExecutor
from langchain.prompts import MessagesPlaceholder
from langchain.schema import SystemMessage
from langchain.prompts.chat import ChatPromptTemplate
from langchain.memory import ConversationSummaryMemory
import warnings
warnings.filterwarnings("ignore")
import json
import streamlit as st

from langchain.agents import AgentExecutor
from langchain.agents.agent import AgentExecutor
from langchain.agents import Tool

from tools.fetch import fetch_whois, geoip_lookup, fetch_threat_feed, IPV4_PATTERN
from tools.score import score_target
from tools.explain import compose_explanation
from tools.general_query import general_query
import memory
import feedback as fb_module
from langchain.memory import ConversationSummaryMemory


# ——————————————————————
# Agent Initialization
# ——————————————————————
tools = [
    Tool(name="fetch_whois", func=fetch_whois, description="Fetch WHOIS data."),
    Tool(name="geoip_lookup", func=geoip_lookup, description="Lookup GeoIP."),
    Tool(name="fetch_threat_feed", func=fetch_threat_feed, description="Fetch threat feed."),
    Tool(name="score_target", func=score_target, description="Compute risk score."),
    Tool.from_function(
        compose_explanation,
        name="compose_explanation",
        description="Explain the risk (data:dict, score:float)."
    ),
    Tool.from_function(
        general_query,
        name="general_query",
        description="Answer general cybersecurity questions."
    ),
]

from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.memory import ConversationSummaryMemory
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.schema import SystemMessage

llm = ChatOpenAI(
    model="gpt-3.5-turbo",
    temperature=0,
    api_key=os.getenv("OPENAI_API_KEY")
)

# Memory
summary_memory = ConversationSummaryMemory(
    llm=llm,
    memory_key="chat_history",
    return_messages=True
)

def generate_combined_input(user_input):
    feedback_lines = []
    for entry in st.session_state.history:
        if entry.get("feedback") is not None:
            result = "correct" if entry["feedback"] else "incorrect"
            line = f'- The response to: "{entry["user"]}" was marked {result}.'
            if entry.get("comments"):
                line += f' Comment: "{entry["comments"]}".'
            feedback_lines.append(line)

    feedback_str = "\n".join(feedback_lines)
    if feedback_str:
        return f"Here is past feedback:\n{feedback_str}\n\nCurrent input:\n{user_input}"
    else:
        return user_input

# Prompt
prompt = ChatPromptTemplate.from_messages([
    SystemMessage(content="You are a helpful cybersecurity assistant. Use any previous feedback to improve."),
    MessagesPlaceholder(variable_name="chat_history"),
    ("user", "{input}"),
    MessagesPlaceholder(variable_name="agent_scratchpad")
])

# Tools (you already have this)
# tools = [...]

# Create agent with tool binding
agent = create_tool_calling_agent(llm=llm, tools=tools, prompt=prompt)

# Create executor with memory
agent_executor = AgentExecutor.from_agent_and_tools(
    agent=agent,
    tools=tools,
    memory=summary_memory,
    verbose=True
)
# ——————————————————————
# Streamlit UI Setup
# ——————————————————————



st.set_page_config(page_title="Maliciousness Chat Agent", layout="wide")
st.title("Agentic Maliciousness Query Chat")
st.markdown("""
    <style>
    .chat-container {
        padding: 10px;
        max-width: 85%;
        margin: 0 auto;
        display: flex;
        flex-direction: column;
    }
    .user-msg, .agent-msg {
        padding: 12px 16px;
        border-radius: 12px;
        margin: 6px 0;
        max-width: 75%;
        color: #f1f1f1;
        font-size: 15px;
        line-height: 1.5;
    }
    .user-msg {
        background-color: #2c3e50;
        align-self: flex-start;
    }
    .agent-msg {
        background-color: #3e3e3e;
        align-self: flex-end;
        margin-left: auto;
    }
    .feedback {
        font-size: 12px;
        color: #b0b0b0;
        margin-top: 4px;
    }
    .chat-divider {
        height: 1px;
        background-color: #444;
        margin: 10px 0;
    }
    </style>
""", unsafe_allow_html=True)

# 1) Create two containers: one for history, one for input form
history_container = st.container()
form_container    = st.container()

# 2) Initialize session state for history
if "history" not in st.session_state:
    st.session_state.history = []

# ——————————————————————
# Helper: extract domain or IP
# ——————————————————————
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE
)
def extract_target(text: str) -> str | None:
    ip = IPV4_PATTERN.search(text)
    if ip:
        return ip.group(0)
    dom = DOMAIN_REGEX.search(text)
    return dom.group(0) if dom else None

# ——————————————————————
# 3) Render chat history in its container
# ——————————————————————

with history_container:
    st.markdown('<div class="chat-container">', unsafe_allow_html=True)
    for idx, entry in enumerate(st.session_state.history):
        st.markdown(f'<div class="user-msg"><strong>You:</strong><br>{entry["user"]}</div>', unsafe_allow_html=True)
        
        st.markdown('<div class="agent-msg">', unsafe_allow_html=True)
        st.markdown("**Agent:**", unsafe_allow_html=True)
        st.markdown(entry.get("agent", ""), unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
        if entry.get("feedback") is None:
            cols = st.columns([1, 1, 6])
            with cols[0]:
                if st.button("✅", key=f"correct_{idx}"):
                    st.session_state.history[idx]["feedback"] = True
            with cols[1]:
                if st.button("❌", key=f"incorrect_{idx}"):
                    st.session_state.history[idx]["feedback"] = False
            with cols[2]:
                comment = st.text_input("Comment:", key=f"comment_{idx}")
                if st.button("Submit", key=f"submit_{idx}"):
                    fb_module.submit_feedback(
                        entry["query_id"],
                        entry.get("verdict"),
                        entry["feedback"],
                        comment
                    )
                    st.session_state.history[idx]["comments"] = comment
                    st.success("Feedback recorded.")
        else:
            status = "✅ correct" if entry["feedback"] else "❌ incorrect"
            st.markdown(f'<div class="feedback">Feedback: {status}</div>', unsafe_allow_html=True)
            if entry.get("comments"):
                st.markdown(f'<div class="feedback">Comment: {entry["comments"]}</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)



# ——————————————————————
# 4) Render input form in its own container (always at bottom)
# ——————————————————————
with form_container.form(key="query_form", clear_on_submit=True):
    user_input = st.text_input("Enter your question or a domain/IP:")
    submitted  = st.form_submit_button("Send")

# ——————————————————————
# 5) Handle form submission
# ——————————————————————
if submitted and user_input:
    # 5a) Append user message placeholder
    st.session_state.history.append({
        "user":     user_input,
        "agent":    "",
        "query_id": None,
        "verdict":  None,
        "feedback": None,
        "comments": None
    })
    combined_input = (
    "When given a natural-language input:\n"
    "- If domain or IP: fetch_whois → geoip_lookup → fetch_threat_feed → score_target → compose_explanation.\n"
    "- Else: general_query\n"
    "Here is the user input: " + user_input
    )
    # 5b) Decide which tool to invoke
    target = extract_target(user_input)
    if target:
        rcombined_input = generate_combined_input(user_input)
        raw = agent_executor.invoke({"input": combined_input})
    else:
        combined_input = generate_combined_input(user_input)
        raw = agent_executor.invoke({"input": combined_input})

    # 5c) Parse JSON for domain-analysis result, else fallback
    try:
        # data = json.loads(raw)
        verdict = raw["verdict"]
        score   = raw["score"]
        reason  = raw["reason"]
        reply = (
            f"**Verdict:** {verdict}\n"
            f"**Score:** {score}/10\n"
            f"**Reason:** {reason}"
        )
        st.session_state.history[-1]["verdict"] = verdict
    except (json.JSONDecodeError, KeyError):
        reply = raw["output"]
        
    # 5d) Log the reply text and update history
    qid = memory.log_query(str(target) or str(user_input), str(reply))
    st.session_state.history[-1].update({
    "agent": reply
,  # assuming 'output' is the key in your agent
    "query_id": qid
    })

    st.rerun()

# ——————————————————————
# 6) Clear Chat History button
# ——————————————————————
if st.button("Clear Chat History"):
    st.session_state.history = []
    with history_container:
        st.empty()
