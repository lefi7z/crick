package handlers_test

import (
	"context"
	"time"

	"github.com/lefi7z/crick/api/middleware"
	"github.com/lefi7z/crick/api/models"
	uuid "github.com/satori/go.uuid"
)

func GetFakeUser() *models.User {
	return models.NewUser("auth0_id", "John Doe", "avatar_url")
}

func AddUserToContext(c context.Context, u *models.User) context.Context {
	return context.WithValue(c, middleware.ContextCurrentUser, u)
}

// MockRepository implements the models.Repository interface for unit testing
// purpose.
type MockRepository struct {
	User         *models.User
	Project      *models.Project
	Team         *models.Team
	Frames       []models.Frame
	NbFrames     int
	Users        models.Users
	Projects     models.Projects
	Teams        models.Teams
	Err          error
	QueryBuilder models.QueryBuilder
	Workloads    *models.Workloads
}

func (r *MockRepository) GetFrames(userID uuid.UUID) ([]models.Frame, error) {
	return r.Frames, r.Err
}

func (r *MockRepository) GetFramesSince(userID uuid.UUID, date time.Time) ([]models.Frame, error) {
	return r.Frames, r.Err
}

func (r *MockRepository) CreateNewFrame(frame models.Frame) error {
	return r.Err
}

func (r *MockRepository) CreateNewProject(name string, userID uuid.UUID) (*models.Project, error) {
	return r.Project, r.Err
}

func (r *MockRepository) GetProjects(userID uuid.UUID) (models.Projects, error) {
	return r.Projects, r.Err
}

func (r *MockRepository) GetProjectByName(userID uuid.UUID, name string) (*models.Project, error) {
	return r.Project, r.Err
}

func (r *MockRepository) CreateNewUser(auth0ID, login, avatarURL string) (*models.User, error) {
	return r.User, r.Err
}

func (r *MockRepository) GetUserByAuth0ID(auth0ID string) (*models.User, error) {
	return r.User, r.Err
}

func (r *MockRepository) GetUserByToken(token string) (*models.User, error) {
	return r.User, r.Err
}

func (r *MockRepository) GetTeamsWithUsers(userID uuid.UUID) (models.Teams, error) {
	return r.Teams, r.Err
}

func (r *MockRepository) CreateNewTeam(team models.Team) error {
	return r.Err
}

func (r *MockRepository) GetUsersByLoginLike(like string) (models.Users, error) {
	return r.Users, r.Err
}

func (r *MockRepository) GetTeamByID(teamID uuid.UUID) (*models.Team, error) {
	return r.Team, r.Err
}

func (r *MockRepository) UpdateTeam(team *models.Team) error {
	return r.Err
}

func (r *MockRepository) GetProjectByID(userID, projectID uuid.UUID) (*models.Project, error) {
	return r.Project, r.Err
}

func (r *MockRepository) GetFramesWithQueryBuilder(qb models.QueryBuilder) (int, []models.Frame, error) {
	r.QueryBuilder = qb
	return r.NbFrames, r.Frames, r.Err
}

func (r *MockRepository) DeleteTeam(team *models.Team) error {
	return r.Err
}

func (r *MockRepository) GetProjectWorkloads(userID, projectID uuid.UUID) (*models.Workloads, error) {
	return r.Workloads, r.Err
}
