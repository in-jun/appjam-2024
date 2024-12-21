package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))

// 구조체 정의
type User struct {
	ID        int    `json:"id"`
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	Nickname  string `json:"nickname" binding:"required"`
	BirthDate string `json:"birthDate" binding:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type Post struct {
	Title           string `json:"title" binding:"required,max=100"`
	Content         string `json:"content" binding:"required,max=500"`
	MealTime        string `json:"mealTime" binding:"required"`
	Location        string `json:"location" binding:"required"`
	MenuName        string `json:"menuName" binding:"required"`
	PreferredAge    int    `json:"preferredAge" binding:"omitempty,min=0,max=100"`
	PreferredGender string `json:"preferredGender" binding:"omitempty"`
}

type ScheduleRequest struct {
	Date     string `json:"date" binding:"required"`
	MealTime string `json:"mealTime" binding:"required"`
	Location string `json:"location" binding:"required"`
	Content  string `json:"content" binding:"required"`
	MenuName string `json:"menuName" binding:"required"`
}

type ProfileUpdate struct {
	Nickname      string   `json:"nickname" binding:"required"`
	Introduction  string   `json:"introduction" binding:"max=100"`
	FavoriteMenus []string `json:"favoriteMenus"`
}

func main() {
	// 데이터베이스 연결
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbName := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		dbUser, dbPassword, dbHost, dbName)

	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// 연결 테스트
	err = db.Ping()
	if err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	// 데이터베이스 초기화
	initDB()

	// Gin 라우터 설정
	r := gin.Default()

	// CORS 미들웨어
	r.Use(corsMiddleware())

	// 공개 라우트
	auth := r.Group("/api/v1/auth")
	{
		auth.POST("/signup", handleSignup)
		auth.POST("/login", handleLogin)
	}

	// 보호된 라우트
	api := r.Group("/api/v1")
	api.Use(authMiddleware())
	{
		api.POST("/posts", createPost)
		api.GET("/posts", getPosts)
		api.GET("/schedules", getSchedules)
		api.POST("/schedules", createSchedule)
		api.PUT("/profile", updateProfile)
		api.GET("/profile", getProfile)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}

func initDB() {
	// users 테이블
	_, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            nickname VARCHAR(255) NOT NULL,
            birth_date DATE NOT NULL,
            introduction TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `)
	if err != nil {
		log.Fatal("Failed to create users table:", err)
	}

	// posts 테이블
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS posts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            meal_time VARCHAR(50) NOT NULL,
            location VARCHAR(255) NOT NULL,
            menu_name VARCHAR(255) NOT NULL,
            preferred_age INT,
            preferred_gender VARCHAR(50),
            author_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users(id)
        )
    `)
	if err != nil {
		log.Fatal("Failed to create posts table:", err)
	}

	// schedules 테이블
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS schedules (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            date DATE NOT NULL,
            meal_time VARCHAR(50) NOT NULL,
            location VARCHAR(255) NOT NULL,
            content VARCHAR(255) NOT NULL,
            menu_name VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE KEY unique_schedule (user_id, date, meal_time)
        )
    `)
	if err != nil {
		log.Fatal("Failed to create schedules table:", err)
	}
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			return
		}

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(bearerToken[1], claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		userID := int(claims["userId"].(float64))
		c.Set("userID", userID)
		c.Next()
	}
}

func handleSignup(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 이메일 중복 검사
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", user.Email).Scan(&count)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already exists"})
		return
	}

	// 비밀번호 해싱
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}

	// 사용자 저장
	result, err := db.Exec(
		"INSERT INTO users (email, password, nickname, birth_date) VALUES (?, ?, ?, ?)",
		user.Email, hashedPassword, user.Nickname, user.BirthDate,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating user"})
		return
	}

	id, _ := result.LastInsertId()
	c.JSON(http.StatusCreated, gin.H{
		"message": "User created successfully",
		"userId":  id,
	})
}

func handleLogin(c *gin.Context) {
	var login LoginRequest
	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	err := db.QueryRow(
		"SELECT id, email, password, nickname, birth_date FROM users WHERE email = ?",
		login.Email,
	).Scan(&user.ID, &user.Email, &user.Password, &user.Nickname, &user.BirthDate)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(login.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// JWT 토큰 생성
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId": user.ID,
		"exp":    time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
		"user": gin.H{
			"id":        user.ID,
			"nickname":  user.Nickname,
			"birthDate": user.BirthDate,
		},
	})
}

func createPost(c *gin.Context) {
	userID, _ := c.Get("userID")

	var post Post
	if err := c.ShouldBindJSON(&post); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 식사 시간 검증
	validMealTimes := map[string]bool{"아침": true, "점심": true, "저녁": true}
	if !validMealTimes[post.MealTime] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid meal time. Use '아침', '점심', or '저녁'"})
		return
	}

	result, err := db.Exec(
		`INSERT INTO posts (title, content, meal_time, location, menu_name, 
            preferred_age, preferred_gender, author_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		post.Title, post.Content, post.MealTime, post.Location, post.MenuName,
		post.PreferredAge, post.PreferredGender, userID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating post"})
		return
	}

	id, _ := result.LastInsertId()
	c.JSON(http.StatusCreated, gin.H{
		"message": "Post created successfully",
		"postId":  id,
	})
}

func getPosts(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "10"))
	mealTime := c.Query("mealTime")

	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 10
	}

	offset := (page - 1) * size

	query := `
        SELECT p.id, p.title, p.meal_time, p.location, p.menu_name,
               u.nickname, TIMESTAMPDIFF(YEAR, u.birth_date, CURDATE()) as age,
               p.created_at
        FROM posts p
        JOIN users u ON p.author_id = u.id
    `

	args := make([]interface{}, 0)
	if mealTime != "" {
		query += " WHERE p.meal_time = ?"
		args = append(args, mealTime)
	}

	query += " ORDER BY p.created_at DESC LIMIT ? OFFSET ?"
	args = append(args, size, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying posts"})
		return
	}
	defer rows.Close()

	var posts []gin.H
	for rows.Next() {
		var post struct {
			ID        int
			Title     string
			MealTime  string
			Location  string
			MenuName  string
			Nickname  string
			Age       int
			CreatedAt time.Time
		}

		if err := rows.Scan(
			&post.ID, &post.Title, &post.MealTime, &post.Location,
			&post.MenuName, &post.Nickname, &post.Age, &post.CreatedAt,
		); err != nil {
			continue
		}

		posts = append(posts, gin.H{
			"id":       post.ID,
			"title":    post.Title,
			"mealTime": post.MealTime,
			"location": post.Location,
			"menuName": post.MenuName,
			"author": gin.H{
				"nickname": post.Nickname,
				"age":      post.Age,
			},
			"createdAt": post.CreatedAt,
		})
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM posts"
	if mealTime != "" {
		countQuery += " WHERE meal_time = ?"
		db.QueryRow(countQuery, mealTime).Scan(&total)
	} else {
		db.QueryRow(countQuery).Scan(&total)
	}

	totalPages := (total + size - 1) / size

	c.JSON(http.StatusOK, gin.H{
		"posts":       posts,
		"totalPages":  totalPages,
		"currentPage": page,
	})
}

func getSchedules(c *gin.Context) {
	userID, _ := c.Get("userID")
	year, _ := strconv.Atoi(c.Query("year"))
	month, _ := strconv.Atoi(c.Query("month"))

	if year == 0 || month == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Year and month are required"})
		return
	}

	rows, err := db.Query(`
        SELECT id, date, meal_time, location, content, menu_name
        FROM schedules
        WHERE user_id = ?
        AND YEAR(date) = ?
        AND MONTH(date) = ?
        ORDER BY date`,
		userID, year, month,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying schedules"})
		return
	}
	defer rows.Close()

	var schedules []gin.H
	for rows.Next() {
		var schedule struct {
			ID       int
			Date     string
			MealTime string
			Location string
			Content  string
			MenuName string
		}

		if err := rows.Scan(
			&schedule.ID, &schedule.Date, &schedule.MealTime,
			&schedule.Location, &schedule.Content, &schedule.MenuName,
		); err != nil {
			continue
		}

		schedules = append(schedules, gin.H{
			"id":       schedule.ID,
			"date":     schedule.Date,
			"mealTime": schedule.MealTime,
			"location": schedule.Location,
			"content":  schedule.Content,
			"menuName": schedule.MenuName,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"schedules": schedules,
	})
}

func createSchedule(c *gin.Context) {
	userID, _ := c.Get("userID")

	var schedule ScheduleRequest
	if err := c.ShouldBindJSON(&schedule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 날짜 형식 검증
	scheduleDate, err := time.Parse("2006-01-02", schedule.Date)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format. Use YYYY-MM-DD"})
		return
	}

	// 과거 날짜 검증
	if scheduleDate.Before(time.Now().Truncate(24 * time.Hour)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot create schedule for past dates"})
		return
	}

	// 식사 시간 검증
	validMealTimes := map[string]bool{"아침": true, "점심": true, "저녁": true}
	if !validMealTimes[schedule.MealTime] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid meal time. Use '아침', '점심', or '저녁'"})
		return
	}

	// 중복 일정 검사
	var count int
	err = db.QueryRow(`
        SELECT COUNT(*) 
        FROM schedules 
        WHERE user_id = ? 
        AND date = ? 
        AND meal_time = ?`,
		userID, schedule.Date, schedule.MealTime,
	).Scan(&count)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Schedule already exists for this time"})
		return
	}

	// 일정 추가
	result, err := db.Exec(`
        INSERT INTO schedules (user_id, date, meal_time, location, content, menu_name)
        VALUES (?, ?, ?, ?, ?, ?)`,
		userID,
		schedule.Date,
		schedule.MealTime,
		schedule.Location,
		schedule.Content,
		schedule.MenuName,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating schedule"})
		return
	}

	id, _ := result.LastInsertId()
	c.JSON(http.StatusCreated, gin.H{
		"message":    "Schedule created successfully",
		"scheduleId": id,
	})
}

func updateProfile(c *gin.Context) {
	userID, _ := c.Get("userID")

	var profile ProfileUpdate
	if err := c.ShouldBindJSON(&profile); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(profile.Introduction) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Introduction cannot exceed 100 characters"})
		return
	}

	_, err := db.Exec(
		"UPDATE users SET nickname = ?, introduction = ? WHERE id = ?",
		profile.Nickname,
		profile.Introduction,
		userID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Profile updated successfully",
	})
}

func getProfile(c *gin.Context) {
	userID, _ := c.Get("userID")

	var profile struct {
		Nickname     string
		BirthDate    string
		Introduction string
	}

	err := db.QueryRow(
		"SELECT nickname, birth_date, COALESCE(introduction, '') FROM users WHERE id = ?",
		userID,
	).Scan(&profile.Nickname, &profile.BirthDate, &profile.Introduction)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching profile"})
		return
	}

	rows, err := db.Query(`
        SELECT date, content, menu_name 
        FROM schedules 
        WHERE user_id = ? 
        ORDER BY date DESC 
        LIMIT 10`,
		userID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching meal history"})
		return
	}
	defer rows.Close()

	var mealHistory []gin.H
	for rows.Next() {
		var meal struct {
			Date     string
			Content  string
			MenuName string
		}

		if err := rows.Scan(&meal.Date, &meal.Content, &meal.MenuName); err != nil {
			continue
		}

		mealHistory = append(mealHistory, gin.H{
			"date":     meal.Date,
			"content":  meal.Content,
			"menuName": meal.MenuName,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"nickname":     profile.Nickname,
		"birthDate":    profile.BirthDate,
		"introduction": profile.Introduction,
		"mealHistory":  mealHistory,
	})
}
