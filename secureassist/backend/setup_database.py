"""
Database Migration and Setup Script
Run this to initialize or update the database
"""

import sys
import os
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_database_url():
    """Get database URL from environment or use default"""
    return os.environ.get(
        'DATABASE_URL',
        'postgresql://secureassist:securepass123@localhost:5432/secureassist_db'
    )


def check_database_connection(engine):
    """Check if database is accessible"""
    try:
        with engine.connect() as conn:
            conn.execute(text('SELECT 1'))
        return True
    except OperationalError as e:
        logger.error(f"Database connection failed: {e}")
        return False


def create_database_if_not_exists():
    """Create database if it doesn't exist"""
    from sqlalchemy_utils import database_exists, create_database
    
    db_url = get_database_url()
    
    if not database_exists(db_url):
        logger.info(f"Creating database...")
        create_database(db_url)
        logger.info("Database created successfully")
    else:
        logger.info("Database already exists")


def run_migrations():
    """Run database migrations"""
    from app import app, db
    
    with app.app_context():
        logger.info("Running database migrations...")
        
        # Create all tables
        db.create_all()
        
        logger.info("Database tables created successfully")


def seed_sample_data():
    """Seed database with sample data"""
    from app import app, db, User, ComplianceRule, KnowledgeBase
    
    with app.app_context():
        logger.info("Seeding sample data...")
        
        # Check if data already exists
        if User.query.count() > 0:
            logger.info("Data already exists, skipping seed")
            return
        
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
        
        # Create sample users
        users_data = [
            ('john.doe', 'john@company.com', 'John Doe', 'Marketing', 'user'),
            ('jane.smith', 'jane@company.com', 'Jane Smith', 'Social Media', 'user'),
            ('bob.manager', 'bob@company.com', 'Bob Manager', 'Management', 'manager'),
        ]
        
        for username, email, full_name, dept, role in users_data:
            user = User(
                username=username,
                email=email,
                full_name=full_name,
                department=dept,
                role=role
            )
            user.set_password('password123')
            db.session.add(user)
        
        # Create compliance rules
        rules_data = [
            {
                'rule_type': 'banned_subreddit',
                'target': 'r/wallstreetbets',
                'reason': 'High-risk community with volatile and promotional content that violates our social media guidelines',
                'severity': 'high',
                'alternative_suggestions': ['r/stocks', 'r/investing', 'r/SecurityAnalysis'],
                'source_document': 'SOP-REDDIT-042'
            },
            {
                'rule_type': 'banned_subreddit',
                'target': 'r/pennystocks',
                'reason': 'High manipulation risk and pump-and-dump schemes that could damage company reputation',
                'severity': 'critical',
                'alternative_suggestions': ['r/stocks', 'r/investing'],
                'source_document': 'SOP-REDDIT-042'
            },
            {
                'rule_type': 'banned_subreddit',
                'target': 'r/cryptocurrency',
                'reason': 'Promotional cryptocurrency content requires special approval per compliance policy',
                'severity': 'medium',
                'alternative_suggestions': ['r/CryptoMarkets', 'r/CryptoTechnology'],
                'source_document': 'SOP-CRYPTO-2024'
            },
            {
                'rule_type': 'prohibited_account',
                'target': '@scam_alerts',
                'reason': 'Known fraudulent account identified by security team',
                'severity': 'critical',
                'alternative_suggestions': [],
                'source_document': 'SOP-SOCIAL-SECURITY-2024'
            },
            {
                'rule_type': 'restricted_content',
                'target': 'financial advice',
                'reason': 'Providing financial advice requires regulatory compliance and legal review',
                'severity': 'high',
                'alternative_suggestions': [],
                'source_document': 'SOP-LEGAL-COMPLIANCE-2024'
            }
        ]
        
        for rule_data in rules_data:
            rule = ComplianceRule(**rule_data)
            db.session.add(rule)
        
        # Create sample knowledge base documents
        kb_docs = [
            {
                'title': 'Reddit Posting Guidelines - SOP-REDDIT-2024',
                'document_type': 'SOP',
                'section': '3.2',
                'version': '2024.1',
                'tags': ['reddit', 'social-media', 'guidelines', 'sop'],
                'content': """
Standard Operating Procedure for Reddit Content Posting

1. OVERVIEW
This document outlines the approved guidelines for posting content on Reddit as a representative of our organization.

2. PROHIBITED SUBREDDITS
The following subreddits are strictly prohibited for company-related content:
- r/wallstreetbets (high-risk, volatile community)
- r/pennystocks (manipulation risk)  
- r/cryptocurrency (for promotional content without approval)

3. APPROVED SUBREDDITS
The following subreddits are approved for content posting:
- r/stocks (financial discussions)
- r/investing (long-term investment discussions)
- r/technology (tech-related content)
- r/business (business news and discussion)

4. CONTENT GUIDELINES
- Always disclose company affiliation when posting
- Follow each subreddit's specific rules strictly
- Avoid promotional or sales-focused language
- Provide genuine value to the community
- Respond to negative comments professionally within 2 hours during business hours
- Escalate threats or serious violations to security team immediately

5. APPROVAL PROCESS
All posts must be reviewed by the social media team before submission. Use the approval workflow in our project management system.

6. ENGAGEMENT RULES
- Be respectful and professional at all times
- Don't engage in arguments or flame wars
- Acknowledge criticism constructively
- Never delete comments unless they violate platform rules
- Document all interactions for compliance records
""",
                'created_by': 1
            },
            {
                'title': 'Community Management Best Practices',
                'document_type': 'guideline',
                'section': '4.1',
                'version': '2024.1',
                'tags': ['community', 'engagement', 'best-practices'],
                'content': """
Community Management Best Practices

1. RESPONSE TIMES
- Critical issues: Immediate response (within 30 minutes)
- Negative comments: Within 2 hours during business hours
- General inquiries: Within 24 hours
- Positive feedback: Acknowledge within 4 hours

2. TONE AND VOICE
- Professional but approachable
- Empathetic to user concerns
- Clear and concise communication
- Avoid jargon unless in technical communities

3. CRISIS MANAGEMENT
If a post goes viral or generates significant negative attention:
1. Immediately notify social media manager
2. Do not delete or hide comments
3. Prepare official statement with PR team
4. Monitor situation hourly
5. Document all interactions

4. ESCALATION TRIGGERS
Escalate immediately if you encounter:
- Legal threats
- Safety concerns
- Potential regulatory violations
- Major brand reputation issues
- Coordinated attacks or brigading
""",
                'created_by': 1
            },
            {
                'title': 'Social Media Disclosure Requirements',
                'document_type': 'policy',
                'section': '2.3',
                'version': '2024.1',
                'tags': ['disclosure', 'compliance', 'legal'],
                'content': """
Social Media Disclosure Requirements

1. MANDATORY DISCLOSURES
All company representatives posting on social media must clearly disclose their affiliation.

Acceptable disclosure formats:
- "I work for [Company Name]"
- "[Company Name] employee here"
- "Disclosure: I'm employed by [Company Name]"

2. PAID PARTNERSHIPS
Any paid or sponsored content must include:
- Clear "Sponsored" or "Paid Partnership" label
- FTC compliance hashtags (#ad, #sponsored)
- Written disclosure in post text

3. TESTIMONIALS AND REVIEWS
When sharing customer testimonials:
- Obtain written consent (Form CT-2024)
- Include disclaimer per this section
- Verify authenticity of testimonial
- Keep records for 7 years

4. REGULATORY COMPLIANCE
Financial services content must comply with:
- SEC regulations for investment advice
- FINRA rules for broker-dealers
- State securities regulations
- Consumer protection laws
""",
                'created_by': 1
            }
        ]
        
        for doc_data in kb_docs:
            doc = KnowledgeBase(**doc_data)
            db.session.add(doc)
        
        # Commit all changes
        db.session.commit()
        
        logger.info("Sample data seeded successfully")
        logger.info("Default credentials:")
        logger.info("  Admin: admin / admin123")
        logger.info("  User: john.doe / password123")


def setup_full_text_search():
    """Setup PostgreSQL full-text search"""
    from app import app, db
    
    with app.app_context():
        logger.info("Setting up full-text search...")
        
        # Create search vector update trigger
        trigger_sql = """
        CREATE OR REPLACE FUNCTION update_search_vector()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.search_vector := 
                setweight(to_tsvector('english', COALESCE(NEW.title, '')), 'A') ||
                setweight(to_tsvector('english', COALESCE(NEW.content, '')), 'B') ||
                setweight(to_tsvector('english', COALESCE(NEW.section, '')), 'C');
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS trig_update_kb_search_vector ON knowledge_base;
        
        CREATE TRIGGER trig_update_kb_search_vector
            BEFORE INSERT OR UPDATE ON knowledge_base
            FOR EACH ROW
            EXECUTE FUNCTION update_search_vector();
        """
        
        try:
            db.session.execute(text(trigger_sql))
            db.session.commit()
            logger.info("Full-text search configured successfully")
        except Exception as e:
            logger.error(f"Error setting up full-text search: {e}")
            db.session.rollback()


def main():
    """Main setup function"""
    logger.info("=" * 60)
    logger.info("SecureAssist Database Setup")
    logger.info("=" * 60)
    
    try:
        # Step 1: Create database if needed
        logger.info("\nStep 1: Checking database...")
        create_database_if_not_exists()
        
        # Step 2: Run migrations
        logger.info("\nStep 2: Running migrations...")
        run_migrations()
        
        # Step 3: Setup full-text search
        logger.info("\nStep 3: Configuring full-text search...")
        setup_full_text_search()
        
        # Step 4: Seed data
        logger.info("\nStep 4: Seeding sample data...")
        seed_sample_data()
        
        logger.info("\n" + "=" * 60)
        logger.info("✅ Database setup completed successfully!")
        logger.info("=" * 60)
        logger.info("\nNext steps:")
        logger.info("1. Start the backend: python app.py")
        logger.info("2. Index knowledge base: python -c 'from ai_service import initialize_ai_service; initialize_ai_service()'")
        logger.info("3. Access the application at http://localhost:5000")
        logger.info("\nDefault login credentials:")
        logger.info("  Username: admin")
        logger.info("  Password: admin123")
        logger.info("\n⚠️  Remember to change default passwords in production!")
        
    except Exception as e:
        logger.error(f"\n❌ Setup failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
