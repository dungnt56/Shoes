package com.vuhien.application.service.impl;

import com.vuhien.application.entity.User;
import com.vuhien.application.exception.BadRequestException;
import com.vuhien.application.model.dto.UserDTO;
import com.vuhien.application.model.mapper.UserMapper;
import com.vuhien.application.model.request.ChangePasswordRequest;
import com.vuhien.application.model.request.CreateUserRequest;
import com.vuhien.application.model.request.UpdateProfileRequest;
import com.vuhien.application.repository.UserRepository;
import com.vuhien.application.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.vuhien.application.config.Contant.LIMIT_USER;

@Component
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public List<UserDTO> getListUsers() {
        List<User> users = userRepository.findAll();
        List<UserDTO> userDTOS = new ArrayList<>();
        for (User user : users) {
            userDTOS.add(UserMapper.toUserDTO(user));
        }
        return userDTOS;
    }

    @Override
    public Page<User> adminListUserPages(String fullName, String phone, String email, Integer page) {
        page--;
        if (page < 0) {
            page = 0;
        }
        Pageable pageable = PageRequest.of(page, LIMIT_USER, Sort.by("created_at").descending());
        return userRepository.adminListUserPages(fullName, phone, email, pageable);
    }

    @Override
    public User createUser(CreateUserRequest createUserRequest) {

        if (createUserRequest.getFullName() == null || createUserRequest.getFullName().isEmpty()) {
            throw new BadRequestException("Họ tên không được để trống");
        }
        if (createUserRequest.getFullName().length() >= 50) {
            throw new BadRequestException("Họ tên không được quá 50 ký tự");
        }

        if (createUserRequest.getEmail() == null || createUserRequest.getEmail().isEmpty()) {
            throw new BadRequestException("Email không được để trống");
        } else if (!isValidEmail(createUserRequest.getEmail())) {
            throw new BadRequestException("Email không hợp lệ");
        }

        if (createUserRequest.getPassword() == null || createUserRequest.getPassword().isEmpty()) {
            throw new BadRequestException("Mật khẩu không được để trống");
        } else if (createUserRequest.getPassword().length() < 6 || createUserRequest.getPassword().length() > 20) {
            throw new BadRequestException("Nhập mật khẩu có độ dài từ 6 đến 20 ký tự");
        }

        if (createUserRequest.getRewritePassword() == null || createUserRequest.getRewritePassword().isEmpty()) {
            throw new BadRequestException("Nhập lại mật khẩu không được để trống");
        } else if (createUserRequest.getRewritePassword().length() < 6 || createUserRequest.getRewritePassword().length() > 20) {
            throw new BadRequestException("Nhập lại mật khẩu có độ dài từ 6 đến 20 ký tự");
        }
        if (!createUserRequest.getRewritePassword().equals(createUserRequest.getPassword())){
            throw new BadRequestException("Mật khẩu không trùng khớp");
        }


        if (createUserRequest.getPhone() == null || createUserRequest.getPhone().isEmpty()) {
            throw new BadRequestException("Số điện thoại không được để trống");
        }
        if (!isValidPhoneNumber(createUserRequest.getPhone())) {
            throw new BadRequestException("Số điện thoại không hợp lệ!");
        }
        User user = UserMapper.toUser(createUserRequest);
        userRepository.save(user);
        return user;
    }

//        User user = userRepository.findByEmail(createUserRequest.getEmail());
//        if (user != null) {
//            throw new BadRequestException("Email đã tồn tại trong hệ thống. Vui lòng sử dụng email khác!");
//        }
    private boolean isValidEmail(String email) {
        // Sử dụng regular expression để kiểm tra định dạng email
        String emailRegex = "^[A-Za-z0-9+_.-]+@(.+)$";
        Pattern pattern = Pattern.compile(emailRegex);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }

    private boolean isValidPhoneNumber(String phone) {
        // Sử dụng regular expression để kiểm tra định dạng số điện thoại
        // Số điện thoại phải bắt đầu bằng "84" hoặc "0" và theo sau bởi 8 chữ số
        String phoneRegex = "^(84|0[3|5|7|8|9])[0-9]{8}$";
        Pattern pattern = Pattern.compile(phoneRegex);
        Matcher matcher = pattern.matcher(phone);
        return matcher.matches();
    }
    @Override
    public void changePassword(User user, ChangePasswordRequest changePasswordRequest) {
        //Kiểm tra mật khẩu
        if (!BCrypt.checkpw(changePasswordRequest.getOldPassword(), user.getPassword())) {
            throw new BadRequestException("Mật khẩu cũ không chính xác");
        }

        String hash = BCrypt.hashpw(changePasswordRequest.getNewPassword(), BCrypt.gensalt(12));
        user.setPassword(hash);
        userRepository.save(user);
    }

    @Override
    public User updateProfile(User user, UpdateProfileRequest updateProfileRequest) {
        user.setFullName(updateProfileRequest.getFullName());
        user.setPhone(updateProfileRequest.getPhone());
        user.setAddress(updateProfileRequest.getAddress());

        return userRepository.save(user);
    }
}
