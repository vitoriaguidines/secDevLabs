package util

import (
	"database/sql"
	"errors"
	"fmt"
	"os"

	"github.com/globocom/secDevLabs/owasp-top10-2021-apps/a3/copy-n-paste/app/hash"
	"github.com/globocom/secDevLabs/owasp-top10-2021-apps/a3/copy-n-paste/app/types"

	"github.com/spf13/viper"

	//setting mysql server for sql.Open function
	_ "github.com/go-sql-driver/mysql"
)

//OpenDBConnection establish a connection with the MySQL DB.
func OpenDBConnection() (*sql.DB, error) {
	connstr := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s",
		os.Getenv("MYSQL_USER"),
		os.Getenv("MYSQL_PASSWORD"),
		viper.GetString("db.host"),
		viper.GetString("db.port"),
		os.Getenv("MYSQL_DATABASE"),
	)
	dbConn, err := sql.Open("mysql", connstr)
	if err != nil {
		return nil, err
	}
	dbConn.SetMaxIdleConns(0)
	dbConn.SetMaxOpenConns(40)
	return dbConn, nil
}

//AuthenticateUser is the function that checks if the given user and password are valid or not
func AuthenticateUser(user string, pass string) (bool, error) {
	if user == "" || pass == "" {
		return false, errors.New("All fields are required")
	}

	dbConn, err := OpenDBConnection()
	if err != nil {
		return false, err
	}
	defer dbConn.Close()

	query := "SELECT id, username, password FROM Users WHERE username = ?" //uso de um placeholder ?
	row := dbConn.QueryRow(query, user) //retorna uma linha do db com base no que foi consultado

	loginAttempt := types.LoginAttempt{} //preenche os campos da tentativa de login com os valores retornados pela linha
	err = row.Scan(&loginAttempt.ID, &loginAttempt.User, &loginAttempt.Pass)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil // No user found
		}
		return false, err
	}

	if hash.CheckPasswordHash(pass, loginAttempt.Pass) { //utiliza hashing para comparar a senha fornecida com o hash armazenado no banco
		return true, nil
	}
	return false, nil
}

//NewUser registers a new user to the db
func NewUser(user string, pass string, passcheck string) (bool, error) {
	if user == "" || pass == "" || passcheck == "" {
		return false, errors.New("All fields are required")
	}
	if pass != passcheck { //tratando erro no caso das senhas não coincidirem
		return false, errors.New("Passwords do not match")
	}

	userExists, err := CheckIfUserExists(user)
	if userExists {
		return false, errors.New("User already exists")
	}

	passHash, err := hash.HashPassword(pass) //evita que senhas sejam armazenas em texto claro
	if err != nil {
		return false, err
	}

	dbConn, err := OpenDBConnection()
	if err != nil {
		return false, err
	}
	defer dbConn.Close()

	query := "INSERT INTO Users (username, password) VALUES (?, ?)"
	_, err = dbConn.Exec(query, user, passHash)
	if err != nil {
		return false, err
	}

	fmt.Println("User created: ", user)
	return true, nil
}

//CheckIfUserExists checks if there is an user with the given username on db
func CheckIfUserExists(username string) (bool, error) {
	dbConn, err := OpenDBConnection()
	if err != nil {
		return false, err
	}
	defer dbConn.Close()

	query := "SELECT username FROM Users WHERE username = ?"
	row := dbConn.QueryRow(query, username)

	var foundUsername string
	err = row.Scan(&foundUsername)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) { //caso nenhum registro seja encontrado, sem expor detalhes
			return false, nil // No user found
		}
		return false, err
	}

	return true, nil
}

// InitDatabase initiates API Database by creating Users table.
func InitDatabase() error {
	dbConn, err := OpenDBConnection()
	if err != nil {
		return fmt.Errorf("OpenDBConnection error: %w", err)
	}
	defer dbConn.Close()

	queryCreate := `CREATE TABLE IF NOT EXISTS Users (
		ID int NOT NULL AUTO_INCREMENT,
		Username varchar(20),
		Password varchar(80),
		PRIMARY KEY (ID)
	)`
	_, err = dbConn.Exec(queryCreate)
	if err != nil {
		return fmt.Errorf("InitDatabase error: %w", err)
	}

	return nil
}