"""
AI Service Module
Offline LLM integration with RAG (Retrieval-Augmented Generation)
"""

import os
import json
from typing import List, Dict, Optional, Tuple
import numpy as np
from datetime import datetime
import logging

# LLM and Embeddings
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
from sentence_transformers import SentenceTransformer
import torch

# Vector Database
import chromadb
from chromadb.config import Settings

# Database integration
from app import db, KnowledgeBase, ComplianceRule

logger = logging.getLogger(__name__)


class AIService:
    """
    Offline AI Service for SecureAssist
    Handles LLM inference, embeddings, and RAG pipeline
    """
    
    def __init__(self, model_path: str = None, embedding_model: str = None):
        """Initialize AI service with offline models"""
        
        # LLM Configuration
        self.model_path = model_path or os.environ.get('LLM_MODEL_PATH', 'mistralai/Mistral-7B-Instruct-v0.2')
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        
        logger.info(f"Initializing AI Service on device: {self.device}")
        
        # Load embedding model for semantic search
        self.embedding_model_name = embedding_model or 'sentence-transformers/all-MiniLM-L6-v2'
        self.embedding_model = SentenceTransformer(self.embedding_model_name)
        
        # Initialize ChromaDB for vector storage
        self.chroma_client = chromadb.Client(Settings(
            chroma_db_impl="duckdb+parquet",
            persist_directory="./chroma_db"
        ))
        
        # Create or get collection
        self.collection = self.chroma_client.get_or_create_collection(
            name="knowledge_base",
            metadata={"hnsw:space": "cosine"}
        )
        
        # Load LLM (lazy loading for better startup time)
        self.tokenizer = None
        self.model = None
        self.llm_pipeline = None
        
        logger.info("AI Service initialized successfully")
    
    def _load_llm(self):
        """Lazy load LLM model"""
        if self.llm_pipeline is None:
            logger.info(f"Loading LLM model: {self.model_path}")
            
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                torch_dtype=torch.float16 if self.device == 'cuda' else torch.float32,
                device_map='auto',
                low_cpu_mem_usage=True
            )
            
            self.llm_pipeline = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                max_new_tokens=512,
                temperature=0.7,
                top_p=0.95,
                repetition_penalty=1.15
            )
            
            logger.info("LLM model loaded successfully")
    
    def index_document(self, doc_id: int, title: str, content: str, metadata: Dict):
        """Index a document into vector database"""
        try:
            # Generate embedding
            embedding = self.embedding_model.encode(content).tolist()
            
            # Add to ChromaDB
            self.collection.add(
                embeddings=[embedding],
                documents=[content],
                metadatas=[{
                    'doc_id': doc_id,
                    'title': title,
                    **metadata
                }],
                ids=[f"doc_{doc_id}"]
            )
            
            logger.info(f"Indexed document: {title} (ID: {doc_id})")
            return True
            
        except Exception as e:
            logger.error(f"Error indexing document {doc_id}: {e}")
            return False
    
    def index_knowledge_base(self):
        """Index all active knowledge base documents"""
        logger.info("Starting knowledge base indexing...")
        
        documents = KnowledgeBase.query.filter_by(status='active').all()
        indexed_count = 0
        
        for doc in documents:
            # Combine title and content for better search
            full_text = f"{doc.title}\n\n{doc.content}"
            
            metadata = {
                'document_type': doc.document_type,
                'section': doc.section or '',
                'version': doc.version or '',
                'file_path': doc.file_path or ''
            }
            
            if self.index_document(doc.id, doc.title, full_text, metadata):
                indexed_count += 1
        
        logger.info(f"Indexed {indexed_count}/{len(documents)} documents")
        return indexed_count
    
    def semantic_search(self, query: str, n_results: int = 5) -> List[Dict]:
        """Perform semantic search on knowledge base"""
        try:
            # Generate query embedding
            query_embedding = self.embedding_model.encode(query).tolist()
            
            # Search in ChromaDB
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results
            )
            
            # Format results
            formatted_results = []
            if results['documents'] and results['documents'][0]:
                for i, doc in enumerate(results['documents'][0]):
                    metadata = results['metadatas'][0][i]
                    distance = results['distances'][0][i] if 'distances' in results else 0
                    
                    formatted_results.append({
                        'doc_id': metadata.get('doc_id'),
                        'title': metadata.get('title'),
                        'content': doc,
                        'document_type': metadata.get('document_type'),
                        'section': metadata.get('section'),
                        'relevance_score': 1 - distance,  # Convert distance to similarity
                        'file_path': metadata.get('file_path')
                    })
            
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error in semantic search: {e}")
            return []
    
    def check_compliance(self, content: str) -> Tuple[List[Dict], List[Dict]]:
        """Check content against compliance rules"""
        violations = []
        warnings = []
        
        content_lower = content.lower()
        
        # Get active compliance rules
        rules = ComplianceRule.query.filter_by(is_active=True).all()
        
        for rule in rules:
            if rule.target.lower() in content_lower:
                violation_data = {
                    'rule_id': rule.id,
                    'type': rule.rule_type,
                    'target': rule.target,
                    'severity': rule.severity,
                    'reason': rule.reason,
                    'alternatives': rule.alternative_suggestions,
                    'source': rule.source_document
                }
                
                if rule.severity in ['high', 'critical']:
                    violations.append(violation_data)
                else:
                    warnings.append(violation_data)
        
        return violations, warnings
    
    def generate_response(
        self, 
        query: str, 
        context_docs: List[Dict] = None,
        compliance_checks: Tuple[List, List] = None,
        max_length: int = 512
    ) -> str:
        """Generate AI response using LLM"""
        
        # Load LLM if not already loaded
        self._load_llm()
        
        # Build prompt with context
        prompt = self._build_prompt(query, context_docs, compliance_checks)
        
        try:
            # Generate response
            response = self.llm_pipeline(
                prompt,
                max_new_tokens=max_length,
                do_sample=True,
                temperature=0.7,
                top_p=0.95
            )
            
            # Extract generated text
            generated_text = response[0]['generated_text']
            
            # Remove the prompt from response
            if prompt in generated_text:
                generated_text = generated_text.replace(prompt, '').strip()
            
            return generated_text
            
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return "I apologize, but I encountered an error processing your request. Please try again."
    
    def _build_prompt(
        self, 
        query: str, 
        context_docs: List[Dict] = None,
        compliance_checks: Tuple[List, List] = None
    ) -> str:
        """Build structured prompt for LLM"""
        
        prompt_parts = [
            "You are SecureAssist, an internal AI assistant for company knowledge management.",
            "Your role is to provide accurate, policy-compliant answers based on internal documentation.",
            ""
        ]
        
        # Add compliance warnings if any
        if compliance_checks:
            violations, warnings = compliance_checks
            
            if violations:
                prompt_parts.append("⚠️ CRITICAL COMPLIANCE ALERT:")
                for v in violations:
                    prompt_parts.append(f"- {v['target']}: {v['reason']}")
                    if v.get('alternatives'):
                        prompt_parts.append(f"  Approved alternatives: {', '.join(v['alternatives'])}")
                prompt_parts.append("")
        
        # Add context from knowledge base
        if context_docs:
            prompt_parts.append("RELEVANT DOCUMENTATION:")
            for i, doc in enumerate(context_docs[:3], 1):  # Top 3 most relevant
                prompt_parts.append(f"\n[Document {i}]: {doc['title']}")
                if doc.get('section'):
                    prompt_parts.append(f"Section: {doc['section']}")
                prompt_parts.append(f"Content: {doc['content'][:500]}...")  # Truncate for context window
                prompt_parts.append("")
        
        # Add user query
        prompt_parts.extend([
            "USER QUERY:",
            query,
            "",
            "ASSISTANT RESPONSE:"
        ])
        
        return "\n".join(prompt_parts)
    
    def process_query(self, query: str, user_id: int) -> Dict:
        """
        Complete query processing pipeline:
        1. Semantic search for relevant documents
        2. Compliance checking
        3. LLM response generation
        """
        
        start_time = datetime.utcnow()
        
        # Step 1: Semantic search
        relevant_docs = self.semantic_search(query, n_results=5)
        
        # Step 2: Compliance check
        violations, warnings = self.check_compliance(query)
        
        # Step 3: Generate response
        response_text = self.generate_response(
            query,
            context_docs=relevant_docs,
            compliance_checks=(violations, warnings)
        )
        
        # Calculate processing time
        processing_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Format sources
        sources = []
        for doc in relevant_docs[:3]:  # Top 3 sources
            sources.append({
                'id': doc['doc_id'],
                'title': doc['title'],
                'document_type': doc.get('document_type'),
                'section': doc.get('section'),
                'file_path': doc.get('file_path'),
                'relevance_score': doc.get('relevance_score', 0)
            })
        
        return {
            'content': response_text,
            'sources': sources,
            'compliance_checks': violations + warnings,
            'violations': violations,
            'warnings': warnings,
            'processing_time': processing_time,
            'query_type': self._classify_query(query)
        }
    
    def _classify_query(self, query: str) -> str:
        """Classify query type for analytics"""
        query_lower = query.lower()
        
        if any(word in query_lower for word in ['can i', 'allowed', 'policy', 'rule', 'prohibited']):
            return 'compliance_check'
        elif any(word in query_lower for word in ['sop', 'procedure', 'guideline', 'how to']):
            return 'sop_search'
        elif any(word in query_lower for word in ['draft', 'write', 'create', 'compose']):
            return 'content_creation'
        elif any(word in query_lower for word in ['analyze', 'review', 'evaluate']):
            return 'content_analysis'
        else:
            return 'general'
    
    def summarize_content(self, content: str, max_length: int = 200) -> str:
        """Summarize long content"""
        self._load_llm()
        
        prompt = f"""Summarize the following content concisely:

{content[:2000]}  # Truncate to avoid context window issues

Summary:"""
        
        try:
            response = self.llm_pipeline(
                prompt,
                max_new_tokens=max_length,
                temperature=0.5
            )
            
            summary = response[0]['generated_text'].replace(prompt, '').strip()
            return summary
            
        except Exception as e:
            logger.error(f"Error summarizing content: {e}")
            return content[:200] + "..."


# Global AI service instance
ai_service = None

def get_ai_service() -> AIService:
    """Get or create AI service singleton"""
    global ai_service
    if ai_service is None:
        ai_service = AIService()
    return ai_service


def initialize_ai_service():
    """Initialize AI service and index knowledge base"""
    logger.info("Initializing AI Service...")
    service = get_ai_service()
    service.index_knowledge_base()
    logger.info("AI Service ready")


if __name__ == '__main__':
    # Test the AI service
    service = AIService()
    
    # Test semantic search
    results = service.semantic_search("What is our Reddit posting policy?")
    print(f"Found {len(results)} relevant documents")
    
    # Test compliance check
    violations, warnings = service.check_compliance("Should I post on r/wallstreetbets?")
    print(f"Violations: {len(violations)}, Warnings: {len(warnings)}")
