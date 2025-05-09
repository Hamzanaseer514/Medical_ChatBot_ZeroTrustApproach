import os
import numpy as np
from langchain.embeddings import HuggingFaceBgeEmbeddings
from langchain_groq import ChatGroq
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.document_loaders import PyPDFLoader
from langchain.vectorstores import FAISS
from langchain.schema import Document  # Import Document class from langchain.schema
from .models import DocumentEmbedding
from sklearn.feature_extraction.text import TfidfVectorizer
import json
from .aes import SimpleEncryptor
import base64


def create_vector_db(pdf_path, user, document):
   
    loader = PyPDFLoader(pdf_path)
    documents = loader.load()
 
    full_text = ""
    for doc in documents:
        full_text += doc.page_content.strip()

    if not full_text:
        raise ValueError("Extracted text is empty or only contains stop words.")


    encryptor = SimpleEncryptor()
    encrypted_bytes = encryptor.encrypt(full_text)
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode()
    
   
    embeddings_model = HuggingFaceBgeEmbeddings(model_name='sentence-transformers/all-MiniLM-L6-v2')


    embedding_vector = embeddings_model.embed_query(full_text)

    doc_embedding = DocumentEmbedding(
        user=user,
        document=document,
        text_chunk=encrypted_base64
    )
    doc_embedding.set_embedding(embedding_vector if isinstance(embedding_vector, list) else embedding_vector.tolist())
    doc_embedding.save()


def generate_embedding(text_chunks):
   
    full_text = " ".join([chunk for chunk in text_chunks if chunk.strip() != ""])  # Join all chunks
    
    if not full_text:
        raise ValueError("Extracted text is empty or only contains stop words.")
    
    
    vectorizer = TfidfVectorizer(stop_words='english')
    embeddings = vectorizer.fit_transform([full_text]).toarray() 
    
  
    return embeddings.tolist()


def load_vector_db(user_id):
   
    doc_embedding = DocumentEmbedding.objects.filter(user_id=user_id).last()
    if not doc_embedding:
        return None

    encrypted_base64 = doc_embedding.text_chunk
    encrypted_bytes = base64.b64decode(encrypted_base64.encode())
    encryptor = SimpleEncryptor()
    decrypted_text = encryptor.decrypt(encrypted_bytes)

  
    embeddings = HuggingFaceBgeEmbeddings(model_name='sentence-transformers/all-MiniLM-L6-v2')
    document_for_faiss = [Document(page_content=decrypted_text)]
    vector_db = FAISS.from_documents(document_for_faiss, embeddings)

    return vector_db



def initialize_llm():

    return ChatGroq(
        temperature=0,
        groq_api_key="use your grok api key",
        model_name="llama-3.3-70b-versatile"
    )


def setup_qa_chain(vector_db, llm):
    retriever = vector_db.as_retriever()
    prompt_template = """You are a compassionate medical chatbot. Respond thoughtfully to the following question based on the user's medical history:
    {context}
    User: {question}
    Chatbot: """
    PROMPT = PromptTemplate(template=prompt_template, input_variables=['context', 'question'])
    return RetrievalQA.from_chain_type(
        llm=llm,
        chain_type="stuff",
        retriever=retriever,
        chain_type_kwargs={"prompt": PROMPT}
    )
