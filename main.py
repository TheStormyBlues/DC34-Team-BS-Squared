from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from langchain_aws import ChatBedrockConverse
from langchain_core.runnables import RunnableLambda
from fetch_url_tool import FetchURLTool
from dotenv import load_dotenv
import os
import git


load_dotenv()

if __name__ == "__main__":
    print("BS-Squared")