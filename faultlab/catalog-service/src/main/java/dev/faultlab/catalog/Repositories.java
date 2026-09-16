package dev.faultlab.catalog;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

interface ProductRepository extends JpaRepository<Product, Long> {}

interface AuthorRepository extends JpaRepository<Author, Long> {}

interface ReviewRepository extends JpaRepository<Review, Long> {
    List<Review> findByProductIdOrderByIdAsc(Long productId);
}
