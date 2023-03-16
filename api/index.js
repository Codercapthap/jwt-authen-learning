const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
const cors = require("cors");

app.use(cors());

app.use(express.json());

const users = [
  {
    id: "1",
    username: "john",
    password: "John0908",
    isAdmin: true,
  },
  {
    id: "2",
    username: "jane",
    password: "Jane0908",
    isAdmin: false,
  },
];

let refreshTokens = [];

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "mySecretKey", {
    expiresIn: "5s",
  });
};
const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "myRefreshKey", {
    expiresIn: "30m",
  });
};

setInterval(() => {
  refreshTokens = refreshTokens.filter((token) => {
    jwt.verify(token, "MyRefreshKey", (err, user) => {
      if (err) {
        return false;
      } else return true;
    });
  });
}, 1800000);

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => {
    return u.username === username && u.password === password;
  });
  if (user) {
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    refreshTokens.push(refreshToken);
    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });
  } else {
    res.status(400).json("Username or password incorrect!");
  }
});

app.post("/api/refresh", (req, res) => {
  // take the refresh token from the user
  const refreshToken = req.body.token;

  // send error if there is no token or it's invalid
  if (!refreshToken) return res.status(401).json("you are not authenticated");
  // console.log(refreshTokens, refreshToken, "63");
  if (!refreshToken.includes(refreshToken)) {
    return res.status(403).json("refresh token is invalid");
  } else {
    jwt.verify(refreshToken, "myRefreshKey", (err, user) => {
      err && console.log(err);
      refreshTokens = refreshTokens.filter((token) => {
        return token !== refreshToken;
      });

      const newAccessToken = generateAccessToken(user);
      const newRefreshToken = generateRefreshToken(user);

      refreshTokens.push(newRefreshToken);
      res
        .status(200)
        .json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
    });
    // if everything is ok, create new access token, refresh token and send to user
  }
});

const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, "mySecretKey", (err, user) => {
      if (err) {
        return res.status(403).json("Token is not valid");
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json("you are not authenticated");
  }
};

app.post("/api/logout", verify, (req, res) => {
  const refreshToken = req.headers.refreshToken;
  refreshTokens = refreshTokens.filter((token) => {
    return token !== refreshToken;
  });
  res.status(200).json("you logged out successfully ");
});

app.delete("/api/users/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json("user has been deleted");
  } else {
    res.status(401).json("you are not allows to delete this user");
  }
});

app.listen(5000, () => {
  console.log("back end is running");
});

// Đăng nhập -> tạo access token + refresh token
// khi làm gì đó -> gửi access token
// khi refresh token -> gửi refresh token ở body ->
//   tạo access token mới, xóa refresh token khỏi mảng, push cái mới vào
// khi logout -> gửi refresh token ở body -> xóa refresh token khỏi mảng
