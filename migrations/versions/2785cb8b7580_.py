"""empty message

Revision ID: 2785cb8b7580
Revises: bf70393ddc30
Create Date: 2019-12-14 22:32:43.778247

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2785cb8b7580'
down_revision = 'bf70393ddc30'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('posts', 'addres',
               existing_type=sa.VARCHAR(length=150),
               nullable=True)
    op.alter_column('posts', 'files',
               existing_type=sa.VARCHAR(length=500),
               nullable=True)
    op.alter_column('posts', 'latc',
               existing_type=sa.VARCHAR(length=20),
               nullable=True)
    op.alter_column('posts', 'longc',
               existing_type=sa.VARCHAR(length=20),
               nullable=True)
    op.alter_column('posts', 'price',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('posts', 'title',
               existing_type=sa.VARCHAR(length=150),
               nullable=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('posts', 'title',
               existing_type=sa.VARCHAR(length=150),
               nullable=False)
    op.alter_column('posts', 'price',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.alter_column('posts', 'longc',
               existing_type=sa.VARCHAR(length=20),
               nullable=False)
    op.alter_column('posts', 'latc',
               existing_type=sa.VARCHAR(length=20),
               nullable=False)
    op.alter_column('posts', 'files',
               existing_type=sa.VARCHAR(length=500),
               nullable=False)
    op.alter_column('posts', 'addres',
               existing_type=sa.VARCHAR(length=150),
               nullable=False)
    # ### end Alembic commands ###
