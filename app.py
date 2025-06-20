from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os


# Get the absolute path to the templates directory
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))

app = Flask(__name__, template_folder=template_dir)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='voter')  # 'voter' or 'admin'
    votes = db.relationship('Vote', backref='voter', lazy=True)

class Election(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    start_datetime = db.Column(db.DateTime, nullable=False)
    end_datetime = db.Column(db.DateTime, nullable=False)
    active = db.Column(db.Boolean, default=True)
    candidates = db.relationship('Candidate', backref='election', lazy=True)
    votes = db.relationship('Vote', backref='election', lazy=True)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    votes = db.relationship('Vote', backref='candidate', lazy=True)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    active_elections = Election.query.filter_by(active=True).all()
    return render_template('index.html', elections=active_elections)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            # Log the login event
            log = LoginLog(
                username=user.username,
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('index'))
        
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/election/<int:election_id>')
@login_required
def view_election(election_id):
    election = Election.query.get_or_404(election_id)
    if not election.active:
        flash('This election is no longer active')
        return redirect(url_for('index'))
    
    # Check if user has already voted
    has_voted = Vote.query.filter_by(
        user_id=current_user.id,
        election_id=election_id
    ).first() is not None
    
    return render_template('election.html', 
                         election=election,
                         has_voted=has_voted)

@app.route('/election/<int:election_id>/vote', methods=['POST'])
@login_required
def cast_vote(election_id):
    election = Election.query.get_or_404(election_id)
    
    if not election.active:
        flash('This election is no longer active')
        return redirect(url_for('index'))
    
    # Check if user has already voted
    if Vote.query.filter_by(user_id=current_user.id, election_id=election_id).first():
        flash('You have already voted in this election')
        return redirect(url_for('view_election', election_id=election_id))
    
    candidate_id = request.form.get('candidate_id')
    if not candidate_id:
        flash('Please select a candidate')
        return redirect(url_for('view_election', election_id=election_id))
    
    # Verify candidate belongs to this election
    candidate = Candidate.query.filter_by(id=candidate_id, election_id=election_id).first()
    if not candidate:
        flash('Invalid candidate selection')
        return redirect(url_for('view_election', election_id=election_id))
    
    vote = Vote(
        user_id=current_user.id,
        election_id=election_id,
        candidate_id=candidate_id
    )
    db.session.add(vote)
    db.session.commit()
    
    flash('Your vote has been recorded successfully!')
    return redirect(url_for('view_election', election_id=election_id))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    
    elections = Election.query.all()
    return render_template('admin_dashboard.html', elections=elections)

@app.route('/admin/election/create', methods=['GET', 'POST'])
@login_required
def create_election():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        start_datetime = datetime.strptime(request.form.get('start_datetime'), '%Y-%m-%dT%H:%M')
        end_datetime = datetime.strptime(request.form.get('end_datetime'), '%Y-%m-%dT%H:%M')
        
        election = Election(
            title=title,
            description=description,
            start_datetime=start_datetime,
            end_datetime=end_datetime
        )
        db.session.add(election)
        db.session.commit()
        
        # Add candidates
        candidate_names = request.form.getlist('candidate_name[]')
        candidate_descriptions = request.form.getlist('candidate_description[]')
        
        for name, desc in zip(candidate_names, candidate_descriptions):
            if name.strip():  # Only add if name is not empty
                candidate = Candidate(
                    name=name,
                    description=desc,
                    election_id=election.id
                )
                db.session.add(candidate)
        
        db.session.commit()
        flash('Election created successfully!')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('create_election.html')

@app.route('/admin/election/<int:election_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_election(election_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    
    election = Election.query.get_or_404(election_id)
    
    if request.method == 'POST':
        election.title = request.form.get('title')
        election.description = request.form.get('description')
        election.start_datetime = datetime.strptime(request.form.get('start_datetime'), '%Y-%m-%dT%H:%M')
        election.end_datetime = datetime.strptime(request.form.get('end_datetime'), '%Y-%m-%dT%H:%M')
        election.active = bool(request.form.get('active'))
        
        db.session.commit()
        flash('Election updated successfully!')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('edit_election.html', election=election)

@app.route('/admin/election/<int:election_id>/results')
@login_required
def view_results(election_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    
    election = Election.query.get_or_404(election_id)
    candidates = election.candidates
    
    # Get vote counts for each candidate
    results = []
    for candidate in candidates:
        vote_count = Vote.query.filter_by(
            election_id=election_id,
            candidate_id=candidate.id
        ).count()
        results.append({
            'candidate': candidate,
            'votes': vote_count
        })
    
    total_votes = sum(r['votes'] for r in results)
    
    return render_template('results.html',
                         election=election,
                         results=results,
                         total_votes=total_votes)

@app.route('/admin/logins')
@login_required
def view_logins():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    logs = LoginLog.query.order_by(LoginLog.login_time.desc()).all()
    return render_template('admin_logins.html', logs=logs)

@app.route('/presentation')
def presentation():
    return render_template('presentation.html')

@app.route('/forms_showcase')
def forms_showcase():
    return render_template('forms_showcase.html')

if __name__ == '__main__':
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()
        
        # Create admin user if none exists
        if not User.query.filter_by(role='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            
            # Create a sample election
            election = Election(
                title='Sample Election',
                description='This is a sample election to demonstrate the system.',
                start_datetime=datetime.utcnow(),
                end_datetime=datetime.utcnow() + timedelta(days=7),
                active=True
            )
            db.session.add(election)
            db.session.commit()
            
            # Add some candidates
            candidates = [
                Candidate(name='Candidate 1', description='First candidate', election_id=election.id),
                Candidate(name='Candidate 2', description='Second candidate', election_id=election.id),
                Candidate(name='Candidate 3', description='Third candidate', election_id=election.id)
            ]
            for candidate in candidates:
                db.session.add(candidate)
            db.session.commit()
    
    app.run(debug=True) 