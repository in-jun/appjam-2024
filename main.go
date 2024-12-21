package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// 구조체 정의
type User struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"password,omitempty"`
	Nickname  string    `json:"nickname"`
	BirthDate string    `json:"birthDate"`
	CreatedAt time.Time `json:"createdAt"`
}

type Post struct {
	ID              int       `json:"id"`
	Title           string    `json:"title"`
	Content         string    `json:"content"`
	MealTime        string    `json:"mealTime"`
	Location        string    `json:"location"`
	MenuName        string    `json:"menuName"`
	PreferredAge    int       `json:"preferredAge"`
	PreferredGender string    `json:"preferredGender"`
	AuthorID        int       `json:"authorId"`
	CreatedAt       time.Time `json:"createdAt"`
}

var db *sql.DB
var jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))

func main() {
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbName := os.Getenv("DB_NAME")

	// MySQL DSN 구성
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		dbUser, dbPassword, dbHost, dbName)

	// DB 연결
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

	// 라우터 설정
	r := mux.NewRouter()

	// CORS 미들웨어 설정
	r.Use(corsMiddleware)

	// API 라우트
	api := r.PathPrefix("/api/v1").Subrouter()

	// 공개 라우트
	api.HandleFunc("/auth/signup", handleSignup).Methods("POST")
	api.HandleFunc("/auth/login", handleLogin).Methods("POST")

	// 보호된 라우트
	protected := api.PathPrefix("").Subrouter()
	protected.Use(authMiddleware)
	protected.HandleFunc("/posts", createPost).Methods("POST")
	protected.HandleFunc("/posts", getPosts).Methods("GET")
	protected.HandleFunc("/schedules", getSchedules).Methods("GET")
	protected.HandleFunc("/profile", updateProfile).Methods("PUT")
	protected.HandleFunc("/profile", getProfile).Methods("GET")

	// 서버 시작
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// 데이터베이스 초기화
func initDB() {
	// users 테이블 생성
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

	// posts 테이블 생성
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

	// schedules 테이블 생성
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS schedules (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            date DATE NOT NULL,
            meal_time VARCHAR(50) NOT NULL,
            location VARCHAR(255) NOT NULL,
            companion VARCHAR(255),
            menu_name VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `)
	if err != nil {
		log.Fatal("Failed to create schedules table:", err)
	}
}

// 미들웨어 함수들
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(bearerToken[1], claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		userID := int(claims["userId"].(float64))
		r.Header.Set("UserID", strconv.Itoa(userID))
		next.ServeHTTP(w, r)
	})
}

// 핸들러 함수들
func handleSignup(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 비밀번호 해싱
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// 사용자 저장
	result, err := db.Exec(
		"INSERT INTO users (email, password, nickname, birth_date) VALUES (?, ?, ?, ?)",
		user.Email, hashedPassword, user.Nickname, user.BirthDate,
	)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	user.ID = int(id)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User created successfully",
		"userId":  user.ID,
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var user User
	err := db.QueryRow("SELECT id, email, password, nickname, birth_date FROM users WHERE email = ?",
		credentials.Email).Scan(&user.ID, &user.Email, &user.Password, &user.Nickname, &user.BirthDate)

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// JWT 토큰 생성
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId": user.ID,
		"exp":    time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Error creating token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"token": tokenString,
		"user": map[string]interface{}{
			"id":        user.ID,
			"nickname":  user.Nickname,
			"birthDate": user.BirthDate,
		},
	})
}

func createPost(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.Atoi(r.Header.Get("UserID"))

	var post Post
	if err := json.NewDecoder(r.Body).Decode(&post); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := db.Exec(
		`INSERT INTO posts (title, content, meal_time, location, menu_name, 
        preferred_age, preferred_gender, author_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		post.Title, post.Content, post.MealTime, post.Location, post.MenuName,
		post.PreferredAge, post.PreferredGender, userID,
	)

	if err != nil {
		http.Error(w, "Error creating post", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Post created successfully",
		"postId":  id,
	})
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("size"))
	mealTime := r.URL.Query().Get("mealTime")

	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 10
	}

	offset := (page - 1) * size

	// 기본 쿼리
	query := `
        SELECT p.id, p.title, p.meal_time, p.location, p.menu_name,
               u.nickname, TIMESTAMPDIFF(YEAR, u.birth_date, CURDATE()) as age,
               p.created_at
        FROM posts p
        JOIN users u ON p.author_id = u.id
    `

	countQuery := "SELECT COUNT(*) FROM posts"

	args := make([]interface{}, 0)
	if mealTime != "" {
		query += " WHERE p.meal_time = ?"
		countQuery += " WHERE meal_time = ?"
		args = append(args, mealTime)
	}

	query += " ORDER BY p.created_at DESC LIMIT ? OFFSET ?"
	args = append(args, size, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, "Error querying posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []map[string]interface{}
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

		posts = append(posts, map[string]interface{}{
			"id":       post.ID,
			"title":    post.Title,
			"mealTime": post.MealTime,
			"location": post.Location,
			"menuName": post.MenuName,
			"author": map[string]interface{}{
				"nickname": post.Nickname,
				"age":      post.Age,
			},
			"createdAt": post.CreatedAt,
		})
	}

	// 전체 페이지 수 계산
	var total int
	if mealTime != "" {
		db.QueryRow(countQuery, mealTime).Scan(&total)
	} else {
		db.QueryRow(countQuery).Scan(&total)
	}

	totalPages := (total + size - 1) / size

	json.NewEncoder(w).Encode(map[string]interface{}{
		"posts":       posts,
		"totalPages":  totalPages,
		"currentPage": page,
	})
}

func getSchedules(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.Atoi(r.Header.Get("UserID"))
	year, _ := strconv.Atoi(r.URL.Query().Get("year"))
	month, _ := strconv.Atoi(r.URL.Query().Get("month"))

	query := `
        SELECT id, date, meal_time, location, companion, menu_name
        FROM schedules
        WHERE user_id = ?
        AND YEAR(date) = ?
        AND MONTH(date) = ?
        ORDER BY date
    `

	rows, err := db.Query(query, userID, year, month)
	if err != nil {
		http.Error(w, "Error querying schedules", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var schedules []map[string]interface{}
	for rows.Next() {
		var schedule struct {
			ID        int
			Date      string
			MealTime  string
			Location  string
			Companion string
			MenuName  string
		}

		if err := rows.Scan(
			&schedule.ID, &schedule.Date, &schedule.MealTime,
			&schedule.Location, &schedule.Companion, &schedule.MenuName,
		); err != nil {
			continue
		}

		schedules = append(schedules, map[string]interface{}{
			"id":        schedule.ID,
			"date":      schedule.Date,
			"mealTime":  schedule.MealTime,
			"location":  schedule.Location,
			"companion": schedule.Companion,
			"menuName":  schedule.MenuName,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"schedules": schedules,
	})
}

func updateProfile(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.Atoi(r.Header.Get("UserID"))

	var profile struct {
		Nickname      string   `json:"nickname"`
		Introduction  string   `json:"introduction"`
		FavoriteMenus []string `json:"favoriteMenus"`
	}

	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 프로필 업데이트
	_, err := db.Exec(
		"UPDATE users SET nickname = ?, introduction = ? WHERE id = ?",
		profile.Nickname, profile.Introduction, userID,
	)

	if err != nil {
		http.Error(w, "Error updating profile", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Profile updated successfully",
	})
}

func getProfile(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.Atoi(r.Header.Get("UserID"))

	// 사용자 기본 정보 조회
	var profile struct {
		Nickname     string `json:"nickname"`
		BirthDate    string `json:"birthDate"`
		Introduction string `json:"introduction"`
	}

	err := db.QueryRow(
		"SELECT nickname, birth_date, COALESCE(introduction, '') FROM users WHERE id = ?",
		userID,
	).Scan(&profile.Nickname, &profile.BirthDate, &profile.Introduction)

	if err != nil {
		http.Error(w, "Error fetching profile", http.StatusInternalServerError)
		return
	}

	// 식사 기록 조회
	rows, err := db.Query(`
        SELECT date, companion, menu_name 
        FROM schedules 
        WHERE user_id = ? 
        ORDER BY date DESC 
        LIMIT 10`,
		userID,
	)
	if err != nil {
		http.Error(w, "Error fetching meal history", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var mealHistory []map[string]string
	for rows.Next() {
		var meal struct {
			Date      string
			Companion string
			MenuName  string
		}

		if err := rows.Scan(&meal.Date, &meal.Companion, &meal.MenuName); err != nil {
			continue
		}

		mealHistory = append(mealHistory, map[string]string{
			"date":      meal.Date,
			"companion": meal.Companion,
			"menuName":  meal.MenuName,
		})
	}

	// 응답 생성
	response := map[string]interface{}{
		"nickname":     profile.Nickname,
		"birthDate":    profile.BirthDate,
		"introduction": profile.Introduction,
		"mealHistory":  mealHistory,
	}

	json.NewEncoder(w).Encode(response)
}
