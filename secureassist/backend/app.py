"""
SecureAssist Backend Application
Main Flask server with API endpoints for internal AI assistant
"""

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import jwt
from functools import wraps
import logging
from typing import Optional, Dict, List
import json

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://localhost/secureassist_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
CORS(app, supports_credentials=True)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(db.Model):
    """User model for authentication and authorization"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(120))
    department = db.Column(db.String(80))
    role = db.Column(db.String(50), default='user')  # user, admin, manager
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    conversations = db.relationship('Conversation', backref='user', lazy='dynamic')
    queries = db.relationship('Query', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'department': self.department,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class KnowledgeBase(db.Model):
    """Knowledge base documents (SOPs, policies, guidelines)"""
    __tablename__ = 'knowledge_base'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    document_type = db.Column(db.String(50))  # SOP, policy, guideline, spreadsheet
    content = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(500))
    section = db.Column(db.String(100))
    version = db.Column(db.String(20))
    status = db.Column(db.String(20), default='active')  # active, archived, draft
    tags = db.Column(db.JSON)
    metadata = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Full-text search
    search_vector = db.Column(db.Text)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'document_type': self.document_type,
            'section': self.section,
            'version': self.version,
            'status': self.status,
            'tags': self.tags,
            'file_path': self.file_path,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


class ComplianceRule(db.Model):
    """Hard-coded compliance rules and restrictions"""
    __tablename__ = 'compliance_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_type = db.Column(db.String(50), nullable=False)  # banned_subreddit, prohibited_account, restricted_content
    target = db.Column(db.String(255), nullable=False)  # The banned item
    reason = db.Column(db.Text)
    severity = db.Column(db.String(20), default='high')  # low, medium, high, critical
    alternative_suggestions = db.Column(db.JSON)  # List of approved alternatives
    source_document = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'rule_type': self.rule_type,
            'target': self.target,
            'reason': self.reason,
            'severity': self.severity,
            'alternatives': self.alternative_suggestions,
            'source_document': self.source_document,
            'is_active': self.is_active
        }


class Conversation(db.Model):
    """User conversation sessions"""
    __tablename__ = 'conversations'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(255))
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    metadata = db.Column(db.JSON)
    
    # Relationships
    messages = db.relationship('Message', backref='conversation', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'started_at': self.started_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'is_active': self.is_active,
            'message_count': self.messages.count()
        }


class Message(db.Model):
    """Individual messages in conversations"""
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # user, assistant, system
    content = db.Column(db.Text, nullable=False)
    sources = db.Column(db.JSON)  # Source documents referenced
    compliance_checks = db.Column(db.JSON)  # Any compliance warnings/blocks
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    processing_time = db.Column(db.Float)  # Response time in seconds
    
    def to_dict(self):
        return {
            'id': self.id,
            'conversation_id': self.conversation_id,
            'role': self.role,
            'content': self.content,
            'sources': self.sources,
            'compliance_checks': self.compliance_checks,
            'timestamp': self.timestamp.isoformat(),
            'processing_time': self.processing_time
        }


class Query(db.Model):
    """Query analytics and performance tracking"""
    __tablename__ = 'queries'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    query_text = db.Column(db.Text, nullable=False)
    query_type = db.Column(db.String(50))  # sop_search, compliance_check, content_draft, etc.
    intent = db.Column(db.String(100))
    results_count = db.Column(db.Integer)
    sources_used = db.Column(db.JSON)
    compliance_triggered = db.Column(db.Boolean, default=False)
    response_time = db.Column(db.Float)
    success = db.Column(db.Boolean, default=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'query_text': self.query_text,
            'query_type': self.query_type,
            'intent': self.intent,
            'results_count': self.results_count,
            'compliance_triggered': self.compliance_triggered,
            'response_time': self.response_time,
            'timestamp': self.timestamp.isoformat()
        }


class AuditLog(db.Model):
    """Audit trail for all system activities"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.Integer)
    details = db.Column(db.JSON)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }


# ============================================================================
# AUTHENTICATION DECORATORS
# ============================================================================

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token.split(' ')[1]
            
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            
            if not current_user or not current_user.is_active:
                return jsonify({'error': 'Invalid token or user inactive'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role not in ['admin', 'manager']:
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    
    return decorated


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['username', 'email', 'password', 'full_name']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if user exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 409
    
    # Create new user
    user = User(
        username=data['username'],
        email=data['email'],
        full_name=data['full_name'],
        department=data.get('department', ''),
        role=data.get('role', 'user')
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    logger.info(f"New user registered: {user.username}")
    
    return jsonify({
        'message': 'User registered successfully',
        'user': user.to_dict()
    }), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login"""
    data = request.get_json()
    
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account is inactive'}), 403
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    }, app.config['JWT_SECRET_KEY'], algorithm='HS256')
    
    # Log audit
    audit = AuditLog(
        user_id=user.id,
        action='login',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    db.session.add(audit)
    db.session.commit()
    
    logger.info(f"User logged in: {user.username}")
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': user.to_dict()
    }), 200


@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout(current_user):
    """User logout"""
    audit = AuditLog(
        user_id=current_user.id,
        action='logout',
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({'message': 'Logged out successfully'}), 200


@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    """Get current user info"""
    return jsonify({'user': current_user.to_dict()}), 200


# ============================================================================
# CHAT/CONVERSATION ENDPOINTS
# ============================================================================

@app.route('/api/conversations', methods=['GET'])
@token_required
def get_conversations(current_user):
    """Get all conversations for current user"""
    conversations = Conversation.query.filter_by(user_id=current_user.id).order_by(Conversation.last_activity.desc()).all()
    return jsonify({
        'conversations': [conv.to_dict() for conv in conversations]
    }), 200


@app.route('/api/conversations', methods=['POST'])
@token_required
def create_conversation(current_user):
    """Create a new conversation"""
    data = request.get_json()
    
    conversation = Conversation(
        user_id=current_user.id,
        title=data.get('title', 'New Conversation'),
        metadata=data.get('metadata', {})
    )
    
    db.session.add(conversation)
    db.session.commit()
    
    logger.info(f"New conversation created: {conversation.id} by {current_user.username}")
    
    return jsonify({
        'message': 'Conversation created',
        'conversation': conversation.to_dict()
    }), 201


@app.route('/api/conversations/<int:conversation_id>', methods=['GET'])
@token_required
def get_conversation(current_user, conversation_id):
    """Get specific conversation with all messages"""
    conversation = Conversation.query.filter_by(id=conversation_id, user_id=current_user.id).first()
    
    if not conversation:
        return jsonify({'error': 'Conversation not found'}), 404
    
    messages = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp).all()
    
    return jsonify({
        'conversation': conversation.to_dict(),
        'messages': [msg.to_dict() for msg in messages]
    }), 200


@app.route('/api/conversations/<int:conversation_id>/messages', methods=['POST'])
@token_required
def send_message(current_user, conversation_id):
    """Send a message in a conversation"""
    conversation = Conversation.query.filter_by(id=conversation_id, user_id=current_user.id).first()
    
    if not conversation:
        return jsonify({'error': 'Conversation not found'}), 404
    
    data = request.get_json()
    
    if not data.get('content'):
        return jsonify({'error': 'Message content required'}), 400
    
    # Create user message
    user_message = Message(
        conversation_id=conversation_id,
        role='user',
        content=data['content'],
        timestamp=datetime.utcnow()
    )
    db.session.add(user_message)
    
    # Process message and generate AI response
    start_time = datetime.utcnow()
    ai_response = process_user_query(data['content'], current_user)
    processing_time = (datetime.utcnow() - start_time).total_seconds()
    
    # Create assistant message
    assistant_message = Message(
        conversation_id=conversation_id,
        role='assistant',
        content=ai_response['content'],
        sources=ai_response.get('sources', []),
        compliance_checks=ai_response.get('compliance_checks', []),
        timestamp=datetime.utcnow(),
        processing_time=processing_time
    )
    db.session.add(assistant_message)
    
    # Update conversation
    conversation.last_activity = datetime.utcnow()
    if not conversation.title or conversation.title == 'New Conversation':
        conversation.title = data['content'][:50] + ('...' if len(data['content']) > 50 else '')
    
    # Log query analytics
    query = Query(
        user_id=current_user.id,
        query_text=data['content'],
        query_type=ai_response.get('query_type', 'general'),
        results_count=len(ai_response.get('sources', [])),
        sources_used=ai_response.get('sources', []),
        compliance_triggered=len(ai_response.get('compliance_checks', [])) > 0,
        response_time=processing_time,
        success=True
    )
    db.session.add(query)
    
    db.session.commit()
    
    return jsonify({
        'user_message': user_message.to_dict(),
        'assistant_message': assistant_message.to_dict()
    }), 201


# ============================================================================
# KNOWLEDGE BASE ENDPOINTS
# ============================================================================

@app.route('/api/knowledge-base', methods=['GET'])
@token_required
def get_knowledge_base(current_user):
    """Search knowledge base"""
    query = request.args.get('q', '')
    doc_type = request.args.get('type', '')
    status = request.args.get('status', 'active')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    kb_query = KnowledgeBase.query.filter_by(status=status)
    
    if doc_type:
        kb_query = kb_query.filter_by(document_type=doc_type)
    
    if query:
        kb_query = kb_query.filter(
            db.or_(
                KnowledgeBase.title.ilike(f'%{query}%'),
                KnowledgeBase.content.ilike(f'%{query}%')
            )
        )
    
    pagination = kb_query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'documents': [doc.to_dict() for doc in pagination.items],
        'total': pagination.total,
        'page': page,
        'pages': pagination.pages
    }), 200


@app.route('/api/knowledge-base/<int:doc_id>', methods=['GET'])
@token_required
def get_document(current_user, doc_id):
    """Get specific knowledge base document"""
    document = KnowledgeBase.query.get(doc_id)
    
    if not document:
        return jsonify({'error': 'Document not found'}), 404
    
    doc_dict = document.to_dict()
    doc_dict['content'] = document.content  # Include full content
    
    return jsonify({'document': doc_dict}), 200


@app.route('/api/knowledge-base', methods=['POST'])
@token_required
@admin_required
def create_document(current_user):
    """Create new knowledge base document"""
    data = request.get_json()
    
    required_fields = ['title', 'content', 'document_type']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    document = KnowledgeBase(
        title=data['title'],
        content=data['content'],
        document_type=data['document_type'],
        section=data.get('section', ''),
        version=data.get('version', '1.0'),
        tags=data.get('tags', []),
        metadata=data.get('metadata', {}),
        created_by=current_user.id
    )
    
    db.session.add(document)
    db.session.commit()
    
    # Log audit
    audit = AuditLog(
        user_id=current_user.id,
        action='create_document',
        resource_type='knowledge_base',
        resource_id=document.id,
        details={'title': document.title}
    )
    db.session.add(audit)
    db.session.commit()
    
    logger.info(f"Document created: {document.title} by {current_user.username}")
    
    return jsonify({
        'message': 'Document created',
        'document': document.to_dict()
    }), 201


# ============================================================================
# COMPLIANCE ENDPOINTS
# ============================================================================

@app.route('/api/compliance/check', methods=['POST'])
@token_required
def check_compliance(current_user):
    """Check content for compliance violations"""
    data = request.get_json()
    
    if not data.get('content'):
        return jsonify({'error': 'Content required'}), 400
    
    content = data['content']
    content_type = data.get('type', 'general')
    
    violations = []
    warnings = []
    
    # Check against active compliance rules
    rules = ComplianceRule.query.filter_by(is_active=True).all()
    
    for rule in rules:
        if rule.target.lower() in content.lower():
            violation = {
                'rule_id': rule.id,
                'type': rule.rule_type,
                'target': rule.target,
                'severity': rule.severity,
                'reason': rule.reason,
                'alternatives': rule.alternative_suggestions,
                'source': rule.source_document
            }
            
            if rule.severity in ['high', 'critical']:
                violations.append(violation)
            else:
                warnings.append(violation)
    
    # Log compliance check
    query = Query(
        user_id=current_user.id,
        query_text=content[:500],
        query_type='compliance_check',
        compliance_triggered=len(violations) > 0,
        response_time=0.1,
        success=True
    )
    db.session.add(query)
    db.session.commit()
    
    return jsonify({
        'compliant': len(violations) == 0,
        'violations': violations,
        'warnings': warnings,
        'checked_at': datetime.utcnow().isoformat()
    }), 200


@app.route('/api/compliance/rules', methods=['GET'])
@token_required
def get_compliance_rules(current_user):
    """Get all compliance rules"""
    rule_type = request.args.get('type', '')
    
    rules_query = ComplianceRule.query.filter_by(is_active=True)
    
    if rule_type:
        rules_query = rules_query.filter_by(rule_type=rule_type)
    
    rules = rules_query.all()
    
    return jsonify({
        'rules': [rule.to_dict() for rule in rules]
    }), 200


@app.route('/api/compliance/rules', methods=['POST'])
@token_required
@admin_required
def create_compliance_rule(current_user):
    """Create new compliance rule"""
    data = request.get_json()
    
    required_fields = ['rule_type', 'target', 'reason']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    rule = ComplianceRule(
        rule_type=data['rule_type'],
        target=data['target'],
        reason=data['reason'],
        severity=data.get('severity', 'high'),
        alternative_suggestions=data.get('alternatives', []),
        source_document=data.get('source_document', '')
    )
    
    db.session.add(rule)
    db.session.commit()
    
    logger.info(f"Compliance rule created: {rule.target} by {current_user.username}")
    
    return jsonify({
        'message': 'Compliance rule created',
        'rule': rule.to_dict()
    }), 201


# ============================================================================
# ANALYTICS ENDPOINTS
# ============================================================================

@app.route('/api/analytics/queries', methods=['GET'])
@token_required
def get_query_analytics(current_user):
    """Get query analytics"""
    days = request.args.get('days', 7, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    
    queries = Query.query.filter(
        Query.timestamp >= start_date
    )
    
    if current_user.role == 'user':
        queries = queries.filter_by(user_id=current_user.id)
    
    total_queries = queries.count()
    avg_response_time = db.session.query(db.func.avg(Query.response_time)).filter(
        Query.timestamp >= start_date
    ).scalar() or 0
    
    compliance_triggered = queries.filter_by(compliance_triggered=True).count()
    
    # Query types breakdown
    query_types = db.session.query(
        Query.query_type,
        db.func.count(Query.id)
    ).filter(
        Query.timestamp >= start_date
    ).group_by(Query.query_type).all()
    
    return jsonify({
        'period_days': days,
        'total_queries': total_queries,
        'avg_response_time': float(avg_response_time),
        'compliance_checks': compliance_triggered,
        'query_types': {qt: count for qt, count in query_types}
    }), 200


@app.route('/api/analytics/users', methods=['GET'])
@token_required
@admin_required
def get_user_analytics(current_user):
    """Get user analytics (admin only)"""
    active_users = User.query.filter_by(is_active=True).count()
    total_users = User.query.count()
    
    # Users by department
    departments = db.session.query(
        User.department,
        db.func.count(User.id)
    ).group_by(User.department).all()
    
    # Recent logins (last 7 days)
    recent_date = datetime.utcnow() - timedelta(days=7)
    recent_logins = User.query.filter(
        User.last_login >= recent_date
    ).count()
    
    return jsonify({
        'total_users': total_users,
        'active_users': active_users,
        'recent_logins': recent_logins,
        'departments': {dept: count for dept, count in departments if dept}
    }), 200


# ============================================================================
# SYSTEM STATUS ENDPOINTS
# ============================================================================

@app.route('/api/system/status', methods=['GET'])
def system_status():
    """Get system status (public endpoint)"""
    try:
        # Check database connection
        db.session.execute(db.text('SELECT 1'))
        db_status = 'online'
    except Exception as e:
        db_status = 'offline'
        logger.error(f"Database error: {e}")
    
    return jsonify({
        'status': 'online',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat()
    }), 200


@app.route('/api/system/health', methods=['GET'])
@token_required
@admin_required
def system_health(current_user):
    """Get detailed system health (admin only)"""
    stats = {
        'total_users': User.query.count(),
        'active_conversations': Conversation.query.filter_by(is_active=True).count(),
        'total_documents': KnowledgeBase.query.filter_by(status='active').count(),
        'compliance_rules': ComplianceRule.query.filter_by(is_active=True).count(),
        'total_queries_24h': Query.query.filter(
            Query.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).count()
    }
    
    return jsonify({
        'status': 'healthy',
        'stats': stats,
        'timestamp': datetime.utcnow().isoformat()
    }), 200


# ============================================================================
# AI PROCESSING FUNCTIONS
# ============================================================================

def process_user_query(query_text: str, user: User) -> Dict:
    """
    Process user query and generate AI response
    This is a placeholder for the actual LLM integration
    """
    query_lower = query_text.lower()
    
    # Check for compliance violations
    compliance_checks = []
    rules = ComplianceRule.query.filter_by(is_active=True).all()
    
    for rule in rules:
        if rule.target.lower() in query_lower:
            compliance_checks.append({
                'type': rule.rule_type,
                'target': rule.target,
                'severity': rule.severity,
                'reason': rule.reason,
                'alternatives': rule.alternative_suggestions
            })
    
    # Search knowledge base
    sources = []
    kb_results = KnowledgeBase.query.filter(
        db.or_(
            KnowledgeBase.title.ilike(f'%{query_text}%'),
            KnowledgeBase.content.ilike(f'%{query_text}%')
        )
    ).limit(3).all()
    
    for doc in kb_results:
        sources.append({
            'id': doc.id,
            'title': doc.title,
            'document_type': doc.document_type,
            'section': doc.section,
            'file_path': doc.file_path
        })
    
    # Generate response (placeholder - integrate actual LLM here)
    if compliance_checks:
        content = f"⚠️ **Compliance Alert**: {compliance_checks[0]['reason']}\n\n"
        if compliance_checks[0]['alternatives']:
            content += f"✅ **Approved alternatives**: {', '.join(compliance_checks[0]['alternatives'])}"
    elif sources:
        content = f"Based on {sources[0]['title']}, here's what I found...\n\n"
        content += "This is a placeholder response. Integrate your offline LLM here."
    else:
        content = "I can help you with that. This is a placeholder response from the backend. Integrate your offline LLM model here."
    
    return {
        'content': content,
        'sources': sources,
        'compliance_checks': compliance_checks,
        'query_type': 'general'
    }


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

@app.cli.command()
def init_db():
    """Initialize the database"""
    db.create_all()
    print("Database initialized!")


@app.cli.command()
def seed_db():
    """Seed the database with sample data"""
    # Create admin user
    admin = User(
        username='admin',
        email='admin@secureassist.local',
        full_name='System Administrator',
        department='IT',
        role='admin'
    )
    admin.set_password('admin123')
    db.session.add(admin)
    
    # Create sample compliance rules
    rules = [
        ComplianceRule(
            rule_type='banned_subreddit',
            target='r/wallstreetbets',
            reason='High-risk community with volatile content (SOP-REDDIT-042)',
            severity='high',
            alternative_suggestions=['r/stocks', 'r/investing'],
            source_document='SOP-REDDIT-042'
        ),
        ComplianceRule(
            rule_type='banned_subreddit',
            target='r/cryptocurrency',
            reason='Promotional content restrictions (SOP-CRYPTO-2024)',
            severity='medium',
            alternative_suggestions=['r/CryptoMarkets'],
            source_document='SOP-CRYPTO-2024'
        )
    ]
    
    for rule in rules:
        db.session.add(rule)
    
    # Create sample knowledge base document
    kb_doc = KnowledgeBase(
        title='Reddit Posting Guidelines - SOP-REDDIT-2024',
        document_type='SOP',
        content='Standard Operating Procedure for Reddit content posting...',
        section='3.2',
        version='2024.1',
        tags=['reddit', 'social-media', 'guidelines'],
        created_by=1
    )
    db.session.add(kb_doc)
    
    db.session.commit()
    print("Database seeded with sample data!")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
