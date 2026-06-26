package base

import (
	"context"
	"testing"
	"time"

	entity "github.com/agentrq/agentrq/backend/internal/data/entity/crud"
	"github.com/agentrq/agentrq/backend/internal/data/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type mockDB struct {
	db *gorm.DB
}

func (m *mockDB) Conn(ctx context.Context) *gorm.DB {
	return m.db
}

func (m *mockDB) Close(ctx context.Context) {}

func TestRepository_GetNextTask(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}

	_ = db.AutoMigrate(&model.Task{})
	repo := New(&mockDB{db: db})

	ctx := context.Background()
	workspaceID := int64(100)
	userID := int64(1)

	// Case 1: No tasks
	_, err = repo.GetNextTask(ctx, workspaceID, userID)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	// Case 2: Tasks exist but none match filters
	db.Create(&model.Task{
		ID:          1,
		WorkspaceID: workspaceID,
		UserID:      userID,
		Status:      "ongoing", // wrong status
		Assignee:    "agent",
	})
	db.Create(&model.Task{
		ID:          2,
		WorkspaceID: workspaceID,
		UserID:      userID,
		Status:      "notstarted",
		Assignee:    "human", // wrong assignee
	})
	db.Create(&model.Task{
		ID:          3,
		WorkspaceID: 200, // wrong workspace
		UserID:      userID,
		Status:      "notstarted",
		Assignee:    "agent",
	})

	_, err = repo.GetNextTask(ctx, workspaceID, userID)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for non-matching tasks, got %v", err)
	}

	// Case 3: Proper match and sorting
	now := time.Now()
	db.Create(&model.Task{
		ID:          10,
		WorkspaceID: workspaceID,
		UserID:      userID,
		Status:      "notstarted",
		Assignee:    "agent",
		SortOrder:   0, // fallback to CreatedAt
		CreatedAt:   now.Add(time.Hour),
	})
	db.Create(&model.Task{
		ID:          11,
		WorkspaceID: workspaceID,
		UserID:      userID,
		Status:      "notstarted",
		Assignee:    "agent",
		SortOrder:   5, // explicit sort order (prioritized)
		CreatedAt:   now.Add(2 * time.Hour),
	})
	db.Create(&model.Task{
		ID:          12,
		WorkspaceID: workspaceID,
		UserID:      userID,
		Status:      "notstarted",
		Assignee:    "agent",
		SortOrder:   10,
		CreatedAt:   now.Add(-time.Hour),
	})

	// Expected order:
	// 1. ID 11 (SortOrder 5)
	// 2. ID 12 (SortOrder 10)
	// 3. ID 10 (SortOrder 0 -> CreatedAt)

	task, err := repo.GetNextTask(ctx, workspaceID, userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.ID != 11 {
		t.Errorf("expected task 11, got %d", task.ID)
	}

	// Case 4: Tie-break by ID
	db.Create(&model.Task{
		ID:          13,
		WorkspaceID: workspaceID,
		UserID:      userID,
		Status:      "notstarted",
		Assignee:    "agent",
		SortOrder:   5,
		CreatedAt:   now.Add(3 * time.Hour),
	})
	// Now 11 and 13 have same SortOrder 5. ID 11 should come first.
	task, _ = repo.GetNextTask(ctx, workspaceID, userID)
	if task.ID != 11 {
		t.Errorf("expected task 11 (tie-break by ID), got %d", task.ID)
	}
}

func TestRepository_UpdateMessageMetadata(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}

	_ = db.AutoMigrate(&model.Message{})
	repo := New(&mockDB{db: db})

	ctx := context.Background()
	taskID := int64(100)
	messageID := int64(500)

	db.Create(&model.Message{
		ID:     messageID,
		TaskID: taskID,
		Text:   "Initial text",
	})

	// Case 1: Success update with correct taskID
	err = repo.UpdateMessageMetadata(ctx, taskID, messageID, []byte(`{"updated":true}`))
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}

	var m model.Message
	db.First(&m, messageID)
	if string(m.Metadata) != `{"updated":true}` {
		t.Errorf("expected metadata to be updated, got %s", string(m.Metadata))
	}

	// Case 2: Update with WRONG taskID (IDOR)
	err = repo.UpdateMessageMetadata(ctx, 999, messageID, []byte(`{"hacked":true}`))
	if err != nil {
		t.Errorf("expected nil error (GORM Update doesn't return error on no rows), got %v", err)
	}

	db.First(&m, messageID)
	if string(m.Metadata) == `{"hacked":true}` {
		t.Error("vulnerability detected: metadata was updated with wrong taskID")
	}
}

func TestRepository_ListTasks_PreloadMessages(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}

	_ = db.AutoMigrate(&model.Task{}, &model.Message{})
	repo := New(&mockDB{db: db})

	ctx := context.Background()
	workspaceID := int64(1)
	userID := int64(10)

	// Create 12 tasks to test batching and limits
	for i := int64(1); i <= 12; i++ {
		db.Create(&model.Task{
			ID:          i,
			WorkspaceID: workspaceID,
			UserID:      userID,
			Title:       "Task",
			Status:      "notstarted",
		})

		// Create a message for the task
		db.Create(&model.Message{
			ID:     100 + i,
			TaskID: i,
			Text:   "Initial msg for task",
		})
	}

	// Case 1: Fetch tasks with PreloadMessages=true
	req := entity.ListTasksRequest{
		WorkspaceID:     workspaceID,
		PreloadMessages: true,
		Limit:           10,
	}

	tasks, err := repo.ListTasks(ctx, req, userID)
	if err != nil {
		t.Fatalf("ListTasks failed: %v", err)
	}

	if len(tasks) != 10 {
		t.Errorf("expected 10 tasks, got %d", len(tasks))
	}

	for _, task := range tasks {
		if len(task.Messages) != 1 {
			t.Errorf("expected 1 preloaded message for task %d, got %d", task.ID, len(task.Messages))
		}
	}
}

func TestRepository_GetWorkspaceTaskCountsByCategory(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}

	_ = db.AutoMigrate(&model.Task{}, &model.Message{})
	repo := New(&mockDB{db: db})

	ctx := context.Background()
	workspaceID := int64(100)
	userID := int64(1)

	// Create test tasks in various categories
	// Ongoing: 2 tasks
	db.Create(&model.Task{ID: 1, WorkspaceID: workspaceID, UserID: userID, Status: "ongoing"})
	db.Create(&model.Task{ID: 2, WorkspaceID: workspaceID, UserID: userID, Status: "blocked"})

	// Not started: 3 tasks
	db.Create(&model.Task{ID: 3, WorkspaceID: workspaceID, UserID: userID, Status: "notstarted", Assignee: "agent"})
	db.Create(&model.Task{ID: 4, WorkspaceID: workspaceID, UserID: userID, Status: "notstarted", Assignee: "agent"})
	db.Create(&model.Task{ID: 5, WorkspaceID: workspaceID, UserID: userID, Status: "notstarted", Assignee: "human"})

	// Scheduled: 1 task
	db.Create(&model.Task{ID: 6, WorkspaceID: workspaceID, UserID: userID, Status: "cron"})

	// Completed: 2 tasks
	db.Create(&model.Task{ID: 7, WorkspaceID: workspaceID, UserID: userID, Status: "completed"})
	db.Create(&model.Task{ID: 8, WorkspaceID: workspaceID, UserID: userID, Status: "rejected"})

	// Pending (Action Required): 1 task
	db.Create(&model.Task{ID: 9, WorkspaceID: workspaceID, UserID: userID, Status: "ongoing"})
	db.Create(&model.Message{
		ID:        901,
		TaskID:    9,
		CreatedAt: time.Now(),
		Metadata:  []byte(`{"type":"permission_request","status":"pending"}`),
	})

	counts, err := repo.GetWorkspaceTaskCountsByCategory(ctx, workspaceID, userID)
	if err != nil {
		t.Fatalf("GetWorkspaceTaskCountsByCategory failed: %v", err)
	}

	if counts["ongoing"] != 3 { // ID 1, 2, 9
		t.Errorf("expected 3 ongoing tasks, got %d", counts["ongoing"])
	}
	if counts["notstarted"] != 3 { // ID 3, 4, 5
		t.Errorf("expected 3 notstarted tasks, got %d", counts["notstarted"])
	}
	if counts["scheduled"] != 1 { // ID 6
		t.Errorf("expected 1 scheduled tasks, got %d", counts["scheduled"])
	}
	if counts["completed"] != 2 { // ID 7, 8
		t.Errorf("expected 2 completed tasks, got %d", counts["completed"])
	}
	if counts["pending"] != 1 { // ID 9
		t.Errorf("expected 1 pending tasks, got %d", counts["pending"])
	}
}

// ── FindAttachmentMetadata ────────────────────────────────────────────────────

func newFindAttachmentDB(t *testing.T) (*gorm.DB, Repository) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	_ = db.AutoMigrate(&model.Workspace{}, &model.Task{}, &model.Message{})
	return db, New(&mockDB{db: db})
}

func TestFindAttachmentMetadata_InTaskAttachments(t *testing.T) {
	db, repo := newFindAttachmentDB(t)

	userID := int64(1)
	db.Create(&model.Workspace{ID: 100, UserID: userID})
	db.Create(&model.Task{
		ID:          1,
		WorkspaceID: 100,
		UserID:      userID,
		Attachments: []byte(`[{"id":"att-task","filename":"report.pdf","mimeType":"application/pdf","data":""}]`),
	})

	filename, mimeType, err := repo.FindAttachmentMetadata(context.Background(), 100, userID, 1, "att-task")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filename != "report.pdf" || mimeType != "application/pdf" {
		t.Errorf("unexpected metadata: %s %s", filename, mimeType)
	}
}

func TestFindAttachmentMetadata_InMessageAttachments(t *testing.T) {
	db, repo := newFindAttachmentDB(t)

	userID := int64(1)
	db.Create(&model.Workspace{ID: 100, UserID: userID})
	db.Create(&model.Task{ID: 2, WorkspaceID: 100, UserID: userID})
	db.Create(&model.Message{
		ID:          201,
		TaskID:      2,
		Attachments: []byte(`[{"id":"att-msg","filename":"photo.png","mimeType":"image/png","data":""}]`),
	})

	filename, mimeType, err := repo.FindAttachmentMetadata(context.Background(), 100, userID, 2, "att-msg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filename != "photo.png" || mimeType != "image/png" {
		t.Errorf("unexpected metadata: %s %s", filename, mimeType)
	}
}

func TestFindAttachmentMetadata_NotFound(t *testing.T) {
	db, repo := newFindAttachmentDB(t)

	userID := int64(1)
	db.Create(&model.Workspace{ID: 100, UserID: userID})
	db.Create(&model.Task{ID: 3, WorkspaceID: 100, UserID: userID, Attachments: []byte(`[{"id":"other"}]`)})

	_, _, err := repo.FindAttachmentMetadata(context.Background(), 100, userID, 3, "att-missing")
	if err == nil {
		t.Fatal("expected error for missing attachment")
	}
}

func TestFindAttachmentMetadata_WrongUser(t *testing.T) {
	db, repo := newFindAttachmentDB(t)

	// Workspace belongs to user 1, but we query as user 2
	db.Create(&model.Workspace{ID: 100, UserID: 1})
	db.Create(&model.Task{
		ID:          4,
		WorkspaceID: 100,
		UserID:      1,
		Attachments: []byte(`[{"id":"att-u1","filename":"private.txt","mimeType":"text/plain","data":""}]`),
	})

	_, _, err := repo.FindAttachmentMetadata(context.Background(), 100, 2, 4, "att-u1")
	if err == nil {
		t.Fatal("expected error when user does not own the workspace")
	}
}

func TestFindAttachmentMetadata_WrongTask(t *testing.T) {
	db, repo := newFindAttachmentDB(t)

	userID := int64(1)
	// Attachment belongs to task 5, but we query for task 6
	db.Create(&model.Workspace{ID: 100, UserID: userID})
	db.Create(&model.Task{ID: 5, WorkspaceID: 100, UserID: userID})
	db.Create(&model.Task{ID: 6, WorkspaceID: 100, UserID: userID})
	db.Create(&model.Message{
		ID:          501,
		TaskID:      5,
		Attachments: []byte(`[{"id":"att-task5","filename":"file.txt","mimeType":"text/plain","data":""}]`),
	})

	_, _, err := repo.FindAttachmentMetadata(context.Background(), 100, userID, 6, "att-task5")
	if err == nil {
		t.Fatal("expected error when querying with wrong task ID")
	}
}

func TestFindAttachmentMetadata_WrongWorkspace(t *testing.T) {
	db, repo := newFindAttachmentDB(t)

	userID := int64(1)
	// Task belongs to workspace 200, but we query with workspace 300 (user doesn't own 300)
	db.Create(&model.Workspace{ID: 200, UserID: userID})
	db.Create(&model.Task{ID: 7, WorkspaceID: 200, UserID: userID})
	db.Create(&model.Message{
		ID:          701,
		TaskID:      7,
		Attachments: []byte(`[{"id":"att-ws200","filename":"secret.pdf","mimeType":"application/pdf","data":""}]`),
	})

	_, _, err := repo.FindAttachmentMetadata(context.Background(), 300, userID, 7, "att-ws200")
	if err == nil {
		t.Fatal("expected error when workspace ID does not match task's workspace")
	}
}
