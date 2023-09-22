package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("my_secret_key")

type Claims struct {
	GUID string `string:"GUID"`
	jwt.RegisteredClaims
}

func Access(w http.ResponseWriter, r *http.Request) {
	GUID := r.URL.Query().Get("GUID")

	accessTime := time.Now().Add(90 * time.Second)
	refreshTime := time.Now().Add(5 * time.Minute)

	// Access token
	access_token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"GUID": GUID,
		"exp":  jwt.NewNumericDate(accessTime),
	})

	AccessTokenString, err := access_token.SignedString(jwtKey)
	if err != nil {
		panic(err)
	}
	// fmt.Println(GUID)
	// fmt.Println("Аксес токен", AccessTokenString)

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    AccessTokenString,
		Expires:  refreshTime,
		HttpOnly: true,
	})

	// Refresh token
	RefreshToken := base64.StdEncoding.EncodeToString([]byte(fmt.Sprint(GUID, time.Now()))) // Выдаем клиенту

	// Используя последние 6 символов выданных с Access токена вставляем в Ревреш для их связывания
	// fmt.Println("Сигнатура 6 последних символов", AccessTokenString[len(AccessTokenString)-6:], len(AccessTokenString))
	RefreshTokenDB := base64.StdEncoding.EncodeToString([]byte(fmt.Sprint(GUID, time.Now(), AccessTokenString[len(AccessTokenString)-6:]))) // Сохраняем в БД
	fmt.Println(RefreshToken)

	// Создание Hash для Refresh токена для записи в БД
	hashRefreshToken, _ := bcrypt.GenerateFromPassword([]byte(RefreshTokenDB), 14)
	fmt.Println("Хэш пароль", string(hashRefreshToken))

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh",
		Value:    RefreshToken,
		Expires:  refreshTime,
		HttpOnly: true,
		// Path:     "/",
	})

	// Сохранение в бд

	ctx := context.TODO()
	opts := options.Client().ApplyURI("mongodb://localhost:27017")

	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		panic(err)
	}

	defer client.Disconnect(ctx)

	// Создание коллекции для хранения Ревреш токена
	tokenDB := client.Database("token")
	tokenCollection := tokenDB.Collection("refreshToken")

	// Добавление в коллекцию
	token := bson.D{
		{"GUID", GUID},
		{"refreshToken", string(hashRefreshToken)},
	}

	rr, err := tokenCollection.InsertOne(ctx, token)
	if err != nil {
		panic(err)
	}
	fmt.Print(rr.InsertedID)

	// проверка должна находиться в обработчике Refresh
	// match := bcrypt.CompareHashAndPassword(hashRefreshToken, []byte(RefreshToken))
	// fmt.Println("Результат проверки хэша:", match)
	// match := bcrypt.CompareHashAndPassword([]byte("$2a$14$5MEWhbTMGTXE8pbWCsYpdO0IKXHthIVD46bRIJCzmSzsHr31rLPL."), []byte("NTExMjAyMy0wOS0yMiAyMDowMTozMi40ODcyODkgKzA4MDAgQ1NUIG09KzMuMTQ2MzYzMTAx[]"))
	// fmt.Println("Результат проверки хэша:", match)

}

// func Welcome(w http.ResponseWriter, r *http.Request) {
// 	c, err := r.Cookie("token")
// 	if err != nil {
// 		panic(err)
// 	}
// 	r.Header.Add("Access", c.Value)
// 	h := r.Header.Get("Access")
// 	claims := &Claims{}
// 	fmt.Println("header", h)
// 	tkn, err := jwt.ParseWithClaims(h, claims, func(token *jwt.Token) (any, error) {
// 		return jwtKey, nil
// 	})
// 	fmt.Println("Suka", c.Name)
// 	fmt.Println("Сигнатура", (tkn.EncodeSegment(tkn.Signature)))
// 	if err != nil {
// 		if err == jwt.ErrSignatureInvalid {
// 			w.WriteHeader(http.StatusUnauthorized)
// 			return
// 		}
// 		w.WriteHeader(http.StatusBadRequest)
// 		fmt.Print(err)
// 		return
// 	}
// 	if !tkn.Valid {
// 		w.WriteHeader(http.StatusUnauthorized)
// 		return
// 	}
// }

func Refresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("refresh")
	c1, err := r.Cookie("token")
	tok := c1.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tok, claims, func(token *jwt.Token) (any, error) {
		return jwtKey, nil
	})
	tknSign := (tkn.Signature)[len(string(tkn.Signature))-6:]

	fmt.Println(tknSign)
	refreshReq := string(append([]byte(c.Value), tknSign...))

	ctx := context.TODO()
	opts := options.Client().ApplyURI("mongodb://localhost:27017")

	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		panic(err)
	}
	GUIDDB := claims.GUID
	fmt.Println(GUIDDB)
	defer client.Disconnect(ctx)

	tCollection := client.Database("token").Collection("refreshToken")

	tokenDB := tCollection.FindOne(ctx, bson.D{{"GUID", bson.D{{"$eq", GUIDDB}}}})
	var exampleResult bson.M
	tokenDB.Decode(&exampleResult)
	hashRefreshToken := exampleResult["refreshToken"].(string)
	// fmt.Println(tokenDB)
	fmt.Println("Ревреш с запроса", refreshReq)
	match := bcrypt.CompareHashAndPassword([]byte(hashRefreshToken), []byte(refreshReq))
	fmt.Println("Результат проверки хэша:", match)

	// Создание новых пар Access Refresh
	if match != nil {

	}

	accessTime := time.Now().Add(90 * time.Second)
	refreshTime := time.Now().Add(5 * time.Minute)

	// Access token
	access_token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"GUID": GUIDDB,
		"exp":  jwt.NewNumericDate(accessTime),
	})

	AccessTokenString, err := access_token.SignedString(jwtKey)
	if err != nil {
		panic(err)
	}
	// fmt.Println(GUID)
	// fmt.Println("Аксес токен", AccessTokenString)

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    AccessTokenString,
		Expires:  refreshTime,
		HttpOnly: true,
	})

	// Refresh token
	RefreshToken := base64.StdEncoding.EncodeToString([]byte(fmt.Sprint(GUIDDB, time.Now()))) // Выдаем клиенту

	// Используя последние 6 символов выданных с Access токена вставляем в Ревреш для их связывания
	// fmt.Println("Сигнатура 6 последних символов", AccessTokenString[len(AccessTokenString)-6:], len(AccessTokenString))
	RefreshTokenDB := base64.StdEncoding.EncodeToString([]byte(fmt.Sprint(GUIDDB, time.Now(), AccessTokenString[len(AccessTokenString)-6:]))) // Сохраняем в БД
	fmt.Println(RefreshToken)

	// Создание Hash для Refresh токена для записи в БД
	NewhashRefreshToken, _ := bcrypt.GenerateFromPassword([]byte(RefreshTokenDB), 14)
	// fmt.Println("Хэш пароль", string(NewhashRefreshToken))

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh",
		Value:    RefreshToken,
		Expires:  refreshTime,
		HttpOnly: true,
		// Path:     "/",
	})

	filter := bson.D{{"GUID", bson.D{{"$eq", GUIDDB}}}}
	update := bson.D{{"$set", bson.D{{"refreshToken", string(NewhashRefreshToken)}}}}
	tCollection.UpdateOne(ctx, filter, update)
}
func main() {
	// Эндпоинты

	http.HandleFunc("/access", Access)
	// http.HandleFunc("/welcome", Welcome)
	http.HandleFunc("/refresh", Refresh)

	// Запуск серва
	http.ListenAndServe("localhost:8080", nil)
}
