package com.memilogistics.shipmentservice.common.mapper;

import com.memilogistics.shipmentservice.companyprofile.dto.CompanyProfileResponse;
import com.memilogistics.shipmentservice.userprofile.dto.UserProfileResponse;
import com.memilogistics.shipmentservice.companyprofile.entity.CompanyProfile;
import com.memilogistics.shipmentservice.userprofile.entity.UserProfile;
import org.springframework.stereotype.Component;

@Component
public class ProfileMapper {
    public UserProfileResponse toUserProfileResponse(UserProfile userProfile) {
        if (userProfile == null) {
            return null;
        }
        UserProfileResponse response = new UserProfileResponse();
        response.setId(userProfile.getProfileId());
        response.setAuthenticationId(userProfile.getAuthenticationId());
        response.setFirstName(userProfile.getFirstName());
        response.setLastName(userProfile.getLastName());

        response.setBusinessName(userProfile.getBusinessName());
        response.setStreet(userProfile.getAddress().getStreet());
        response.setCity(userProfile.getAddress().getCity());
        response.setZip(userProfile.getAddress().getZip());
        response.setState(userProfile.getAddress().getState());
        response.setCountry(userProfile.getAddress().getCountry());
        response.setPhoneNumber(userProfile.getAddress().getPhoneNumber());
        return response;
    }

    public CompanyProfileResponse toCompanyProfileResponse(CompanyProfile companyProfile) {
        if (companyProfile == null) {
            return null;
        }
        CompanyProfileResponse response = new CompanyProfileResponse();
        response.setId(companyProfile.getCompanyProfileId());
        response.setCompanyName(companyProfile.getCompanyName());
        response.setCompanyEmail(companyProfile.getCompanyEmail());
        response.setStreet(companyProfile.getAddress().getStreet());
        response.setCity(companyProfile.getAddress().getCity());
        response.setState(companyProfile.getAddress().getState());
        response.setCountry(companyProfile.getAddress().getCountry());
        response.setZip(companyProfile.getAddress().getZip());
        response.setPhoneNumber(companyProfile.getAddress().getPhoneNumber());
        return response;
    }


}

